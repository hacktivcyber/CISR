#!/usr/bin/env python3
import argparse
import subprocess
import re
import sys
import os
import tempfile

def get_clean_name(url):
    clean = re.sub(r'https?://', '', url)
    clean = re.sub(r'[^a-zA-Z0-9.-]', '_', clean)
    return clean.strip('_')

def detect_filter(target_url, mode, debug=False):
    """Identify the consistent response Size for filter-out noise."""
    canary_words = "aaaaaa\nzzzzzz\nbloncky\nhuanung\nfrigole"
    host_domain = re.sub(r'https?://', '', target_url).split('/')[0]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tf:
        tf.write(canary_words)
        temp_wordlist = tf.name

    # Updated command logic as requested: using -mc all and -v
    if mode == "dir":
        base_url = target_url.rstrip('/')
        cmd = ["ffuf", "-w", temp_wordlist, "-u", f"{base_url}/FUZZ", "-v", "-mc", "all"]
    else:
        cmd = ["ffuf", "-w", temp_wordlist, "-u", target_url, "-H", f"Host: FUZZ.{host_domain}", "-v", "-mc", "all"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        stdout = result.stdout
        stderr = result.stderr

        if debug:
            print(f"\n--- DEBUG: {mode.upper()} TEST ---")
            print(f"Command: {' '.join(cmd)}")
            print(stdout)
            if stderr: print(f"STDERR: {stderr}")
            print("----------------------------\n")

        # Extraction logic switched to 'Size' instead of 'Lines'
        found_sizes = re.findall(r"Size:\s*(\d+)", stdout)

        if os.path.exists(temp_wordlist):
            os.remove(temp_wordlist)

        if not found_sizes:
            return "0"

        unique_values = set(found_sizes)
        # If the target returns multiple 404 sizes (e.g., two different error pages)
        # We return them comma-separated so ffuf filters both
        if len(unique_values) >= 1:
            return ",".join(list(unique_values))
        return "0"

    except Exception as e:
        if debug: print(f"[-] Execution Error: {e}")
        if os.path.exists(temp_wordlist): os.remove(temp_wordlist)
        return "0"

def main():
    parser = argparse.ArgumentParser(description="FFUF Wrapper with Auto-FS (Size) detection")
    parser.add_argument("target_url", help="Target URL")
    parser.add_argument("-d", "--dir_fs", help="Manual -fs for Directory", default=None)
    parser.add_argument("-s", "--sub_fs", help="Manual -fs for Subdomain", default=None)
    parser.add_argument("-e", "--extensions", help="Comma separated extensions", default=None)
    parser.add_argument("--dir_dict", help="Path to directory wordlist", default="/home/kali/Desktop/dirFUZZ.txt")
    parser.add_argument("--sub_dict", help="Path to subdomain wordlist", default="/home/kali/Desktop/subFUZZ.txt")
    parser.add_argument("-debug", action="store_true", help="Show raw test responses")
    
    args = parser.parse_args()
    
    target = args.target_url if args.target_url.startswith("http") else f"http://{args.target_url}"
    clean_name = get_clean_name(target)
    
    dir_dict = args.dir_dict
    sub_dict = args.sub_dict

    print(f"--- Analysis Phase ---")
    
    # 1. Directory Detection (Filtering by Size)
    final_dir_fs = args.dir_fs if args.dir_fs else detect_filter(target, "dir", args.debug)
    print(f"[+] Directory Size Filter: -fs {final_dir_fs}")

    # 2. Subdomain Detection (Filtering by Size)
    final_sub_fs = args.sub_fs if args.sub_fs else detect_filter(target, "sub", args.debug)
    print(f"[+] Subdomain Size Filter: -fs {final_sub_fs}")

    # 3. Main Directory Fuzz
    dir_out = f"/home/kali/Desktop/{clean_name}_dir_results.txt"
    dir_cmd = ["ffuf", "-w", dir_dict, "-u", f"{target.rstrip('/')}/FUZZ", "-c", "-v", 
               "-o", dir_out, "-of", "csv", "-mc", "200-299,301,302,307,400,401,403,405,418,429,500,502,503", "-fs", final_dir_fs]
    if args.extensions:
        dir_cmd += ["-e", args.extensions]
    
    print(f"\n[+] Running Directory Fuzzing...")
    subprocess.run(dir_cmd)

    # 4. Main Subdomain Fuzz
    host_domain = re.sub(r'https?://', '', target).split('/')[0]
    sub_out = f"/home/kali/Desktop/{clean_name}_sub_results.txt"
    sub_cmd = ["ffuf", "-w", sub_dict, "-u", target, "-H", f"Host: FUZZ.{host_domain}", 
               "-c", "-v", "-o", sub_out, "-of", "csv", "-mc", "200-299,301,302,307,400,401,403,405,418,429,500,502,503", "-fs", final_sub_fs]
    
    print(f"\n[+] Running Subdomain Fuzzing...")
    subprocess.run(sub_cmd)

if __name__ == "__main__":
    main()
