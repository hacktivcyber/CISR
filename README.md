# CISR
Cyber Intelligence, Surveillance, and Reconnaissance (C-ISR) Scripts

This repository contains specialized tools designed to streamline the reconnaissance phase of security assessments. By combining rapid port discovery with intelligent service triage and automated web fuzzing, this suite reduces manual overhead and ensures consistent methodology.

---

## 🏗️ Core Components

### 1. `recon.sh` (The Orchestrator)
A comprehensive Bash script that manages the initial discovery and deep enumeration phases. It categorizes findings using a "Truth Table" logic to prioritize high-value targets.

* **Phase 1: TCP Discovery:** High-speed port scanning using `nmap`.
* **Phase 2: Redirect Check:** Automatically identifies HTTP/HTTPS redirects and updates `/etc/hosts` if new domains are detected.
* **Phase 3: Deep Dive:** Runs service-specific nmap scripts (banner, default & vulners) and cross-references results with `searchsploit` for known exploits.
* **Phase 4: Smart UDP:** Scans 1000 common UDP ports while excluding previously discovered TCP ports to maximize efficiency.
* **Triage Engine:** Color-codes results (Green/Yellow/Orange/Red) based on whether service signatures match expected port behaviors.

#### Arguments
| Argument | Description |
| :--- | :--- |
| `<target-ip>` | The IP address of the target host. |
| `<machine-name>` | A friendly name for the target used for directory and file naming. |

---

### 2. `fuzz.py` (The Intelligent Fuzzer)
A Python wrapper for `ffuf` that automates noise reduction. It performs an initial "analysis phase" to detect response sizes for non-existent resources, preventing false positives.

* **Auto-FS Detection:** Automatically identifies and sets the `-fs` (filter size) flag for both directory and subdomain fuzzing.
* **Dual-Mode Fuzzing:** Handles both directory discovery and virtual host (subdomain) enumeration in a single execution.
* **Adaptive Filtering:** Handles targets that return multiple different sizes for 404/error pages by generating comma-separated filters.

#### Arguments
| Argument | Description |
| :--- | :--- |
| `target_url` | The URL of the target (e.g., http://10.10.10.10). |
| `-d`, `--dir_fs` | Manual `-fs` override for Directory fuzzing. |
| `-s`, `--sub_fs` | Manual `-fs` override for Subdomain fuzzing. |
| `-e`, `--extensions` | Comma-separated list of extensions to fuzz (e.g., .php,.txt). |
| `--dir_dict` | Path to the directory wordlist (Default: `./dirFUZZ.txt`). |
| `--sub_dict` | Path to the subdomain wordlist (Default: `./subFUZZ.txt`). |
| `-debug` | Optional flag to show raw test responses during the analysis phase. |

---

## 🚀 Quick Start

### Prerequisites
Ensure the following tools are installed and available in your `$PATH`:
* `nmap`, `ffuf`, `searchsploit`, `curl`, `python3`

### Usage

**1. Run the full reconnaissance suite:**
```bash
chmod +x recon.sh
./recon.sh <target-ip> <machine-name>

This will create a directory named recon_<machine-name> containing all logs, grepable outputs, and XML results.

2. Standalone Web Fuzzing:
If recon.sh identifies a web service, it will suggest a fuzz.py command. You can also run it manually:

Bash
python3 fuzz.py [http://example.com](http://example.com) --dir_dict /path/to/wordlist.txt
📊 Output Structure
The suite organizes results into a dedicated folder to maintain a clean workspace:

Plaintext
recon_targetname/
├── targetname_tcp_ports.grep    # Initial rapid scan
├── targetname_tcp_detailed.nmap # Service versioning & scripts
├── targetname_searchsploit.txt  # Potential exploit matches
└── targetname_dir_results.txt   # CSV output from ffuf

⚖️ License
This project is licensed under the GNU GPL v3.0.
