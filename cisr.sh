#!/bin/bash

# --- COLOR DEFINITIONS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Check for two arguments
if [ "$#" -ne 2 ]; then
    echo -e "${RED}Usage: $0 <target-ip> <machine-name>${NC}"
    exit 1
fi

TARGET=$1
NAME=$2
DIR="recon_$NAME"
PREFIX="${NAME}_"
TOTAL_START=$(date +%s)

mkdir -p "$DIR"
echo -e "${BLUE}${BOLD}[+] Initializing Pro-Recon on $NAME ($TARGET)${NC}"
echo -e "${BLUE}[+] Global Start Time: $(date)${NC}\n"

# --- PHASE 1: TCP DISCOVERY ---
PHASE1_START=$(date +%s)
echo -e "${CYAN}[!] Phase 1: Rapid TCP Discovery Starting...${NC}"
CMD_TCP="sudo nmap -p- --min-rate 5000 -T4 -oG $DIR/${PREFIX}tcp_ports.grep $TARGET"
echo -e "  [Run]: $CMD_TCP"
$CMD_TCP > /dev/null

TCP_PORTS=$(grep -a "Ports:" "$DIR/${PREFIX}tcp_ports.grep" | grep -oP '\d+(?=/open/tcp)' | tr '\n' ',' | sed 's/,$//')

PHASE1_END=$(date +%s)
echo -e "${GREEN}[+] Phase 1 Complete in $((PHASE1_END - PHASE1_START)) seconds.${NC}"

if [ -z "$TCP_PORTS" ]; then
    echo -e "${RED}[- ] No TCP ports found. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}${BOLD}[***] OPEN PORTS: $TCP_PORTS${NC}"

# --- PHASE 2: REDIRECT & HOSTS CHECK ---
PHASE2_START=$(date +%s)
echo -e "\n${CYAN}[!] Phase 2: Domain Redirect Check Starting...${NC}"

for port in 80 443 8080 8443; do
    if [[ ",$TCP_PORTS," == *",$port,"* ]]; then
        DOMAIN=$(curl -Is --connect-timeout 5 http://$TARGET:$port 2>/dev/null | grep -i '^Location' | awk -F'[/:]' '{print $4}' | tr -d '\r')
        
        if [[ ! -z "$DOMAIN" && "$DOMAIN" != "$TARGET" ]]; then
            echo -e "${MAGENTA}${BOLD}[ALERT] Port $port: Redirect detected to: $DOMAIN${NC}"
            if ! grep -q "$DOMAIN" /etc/hosts; then
                echo -e "  ${YELLOW}[+] Adding $DOMAIN to /etc/hosts...${NC}"
                echo "$TARGET $DOMAIN" | sudo tee -a /etc/hosts > /dev/null
            fi
        else
            echo -e "${GREEN}[INFO] Port $port: No redirect detected.${NC}"
        fi
    fi
done

PHASE2_END=$(date +%s)
echo -e "${GREEN}[+] Phase 2 Complete in $((PHASE2_END - PHASE2_START)) seconds.${NC}"

# --- PHASE 3: DEEP ENUMERATION & SEARCHSPLOIT ---
PHASE3_START=$(date +%s)
echo -e "\n${CYAN}[!] Phase 3: Deep Dive & Searchsploit Starting...${NC}"
CMD_DEEP="sudo nmap -sC -sV -p$TCP_PORTS --script=banner,default,vulners -oN $DIR/${PREFIX}tcp_detailed.nmap -oX $DIR/${PREFIX}tcp_detailed.xml $TARGET"
echo -e "  [Run]: $CMD_DEEP"
$CMD_DEEP > /dev/null

# Priority Alerts & Methodology Guidance
IFS=',' read -ra ADDR <<< "$TCP_PORTS"
echo -e "\n${MAGENTA}${BOLD}[!] METHODOLOGY GUIDANCE:${NC}"

for port in "${ADDR[@]}"; do
    case $port in
        21) 
            echo -e "${YELLOW}>> [FTP] Check Anonymous Logon: ${NC}ftp $TARGET" 
            ;;
        53) 
            echo -e "${YELLOW}>> [DNS] Attempt Zone Transfer: ${NC}dig axfr @$TARGET \$DOMAIN" 
            ;;
        80|443|8080|8443) 
            echo -e "${YELLOW}>> [HTTP] Run Directory Fuzzing: ${NC}python3 your_fuzzer.py $TARGET $port"
            echo -e "${YELLOW}>> [HTTP] Fingerprint Tech Stack: ${NC}whatweb -a 3 http://$TARGET:$port" 
            ;;
        139|445) 
            echo -e "${YELLOW}>> [SMB] Check Null Session: ${NC}smbclient -L //$TARGET -N"
            echo -e "${YELLOW}>> [SMB] Enum Users/Shares: ${NC}enum4linux-ng -A $TARGET" 
            ;;
        161) 
            echo -e "${YELLOW}>> [SNMP] Walk Community String: ${NC}snmp-check $TARGET" 
            ;;
        389|636) 
            echo -e "${YELLOW}>> [LDAP] Check Null Bind: ${NC}ldapsearch -x -H ldap://$TARGET -b \"dc=example,dc=com\"" 
            ;;
        2049) 
            echo -e "${YELLOW}>> [NFS] Check Exports: ${NC}showmount -e $TARGET" 
            ;;
        3389) 
            echo -e "${YELLOW}>> [RDP] Check BlueKeep (CVE-2019-0708): ${NC}nmap -p 3389 --script rdp-vuln-ms12-020 $TARGET" 
            ;;
        6379) 
            echo -e "${YELLOW}>> [REDIS] Check No-Auth: ${NC}redis-cli -h $TARGET info" 
            ;;
    esac
done

echo -e "${CYAN}[!] Compiling Exploit Database Leads via XML...${NC}"

searchsploit --nmap "$DIR/${PREFIX}tcp_detailed.xml" --disable-colour > "$DIR/${PREFIX}searchsploit_results.txt" 2>/dev/null

# Clean up: Highlight if any exploits were actually found
if [ -s "$DIR/${PREFIX}searchsploit_results.txt" ]; then
    echo -e "${RED}[+] Exploits found! Check $DIR/${PREFIX}searchsploit_results.txt${NC}"
else
    echo -e "${GREEN}[-] No direct exploit matches found in Searchsploit.${NC}"
fi

PHASE3_END=$(date +%s)
echo -e "${GREEN}[+] Phase 3 Complete in $((PHASE3_END - PHASE3_START)) seconds.${NC}"

# --- PHASE 4: SMART UDP ---
PHASE4_START=$(date +%s)
echo -e "\n${CYAN}[!] Phase 4: Smart UDP (Top 100) Starting...${NC}"
sudo nmap -sU --top-ports 100 -T4 --exclude-ports $TCP_PORTS -oN $DIR/${PREFIX}udp_scan.nmap $TARGET > /dev/null
PHASE4_END=$(date +%s)
echo -e "${GREEN}[+] Phase 4 Complete in $((PHASE4_END - PHASE4_START)) seconds.${NC}"

# --- FINAL SUMMARY ---
TOTAL_END=$(date +%s)
TOTAL_RUNTIME=$((TOTAL_END - TOTAL_START))

echo -e "\n${BLUE}${BOLD}----------------------------------------------------${NC}"
echo -e "${GREEN}${BOLD}[+] RECON COMPLETE FOR $NAME${NC}"
echo -e "${CYAN}[i] Total Runtime: $TOTAL_RUNTIME seconds${NC}"
echo -e "${CYAN}[i] Final Finish: $(date)${NC}"
echo -e "    - Results: $DIR/"
echo -e "${BLUE}${BOLD}----------------------------------------------------${NC}"
