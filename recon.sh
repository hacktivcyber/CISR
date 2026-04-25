#!/bin/bash

# --- COLOR DEFINITIONS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
ORANGE='\033[38;5;208m'
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
echo -e "\n${MAGENTA}${BOLD}[!] COMPREHENSIVE SERVICE EVALUATION & TRIAGE:${NC}"
echo -e "${CYAN}PORT\tSTATE\tSERVICE\t\tSTATUS & RECOMMENDATION${NC}"
echo -e "${CYAN}------------------------------------------------------------${NC}"

grep -v "^#" "$DIR/${PREFIX}tcp_ports.grep" | grep "Ports:" | sed 's/.*Ports: //' | tr ',' '\n' | while read -r line; do
    PORT=$(echo $line | cut -d'/' -f1 | xargs)
    STATE=$(echo $line | cut -d'/' -f2 | xargs)
    SERVICE_DET=$(echo $line | cut -d'/' -f5 | xargs)

    KNOWN_PORT=false
    KNOWN_SERVICE=false
    RECOMMENDATION=""

    # --- 1. COMPREHENSIVE KNOWN PORTS TABLE ---
    # Includes: Infra, DBs, Middleware, and Common High-Port Web/Dev tools
    case $PORT in
        21|22|23|25|53|79|80|88|110|111|135|139|143|161|389|443|445|465|587|593|631|636|873|993|995|1080|1433|1521|2049|3306|3389|3690|4444|5000|5432|5900|5985|5986|6379|8000|8080|8081|8443|8888|9000|9200|10000|27017)
            KNOWN_PORT=true ;;
    esac

    # --- 2. COMPREHENSIVE SERVICE LOOKUP & COMMANDS ---
    case $SERVICE_DET in
        ftp)
            KNOWN_SERVICE=true
            RECOMMENDATION="nmap -sV --script ftp-anon -p $PORT $TARGET" ;;
        ssh)
            KNOWN_SERVICE=true
            RECOMMENDATION="ssh -v -o PreferredAuthentications=password $TARGET -p $PORT" ;;
        telnet)
            KNOWN_SERVICE=true
            RECOMMENDATION="telnet $TARGET $PORT" ;;
        smtp|submission)
            KNOWN_SERVICE=true
            RECOMMENDATION="nmap -p $PORT --script smtp-enum-users $TARGET" ;;
        domain)
            KNOWN_SERVICE=true
            RECOMMENDATION="dig axfr @$TARGET \$DOMAIN" ;;
        finger)
            KNOWN_SERVICE=true
            RECOMMENDATION="finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t $TARGET" ;;
        http*|ssl/http*|https*|jetty|nginx|apache|vnc-http|uwsgi)
            KNOWN_SERVICE=true
            PROTO="http"; [[ "$SERVICE_DET" == *"ssl"* || "$SERVICE_DET" == *"https"* || "$PORT" == "443" || "$PORT" == "8443" ]] && PROTO="https"
            RECOMMENDATION="python3 fuzz.py $PROTO://$TARGET:$PORT" ;;
        rpcbind|sunrpc)
            KNOWN_SERVICE=true
            RECOMMENDATION="rpcinfo -p $TARGET" ;;
        kerberos*)
            KNOWN_SERVICE=true
            RECOMMENDATION="nmap -p $PORT --script krb5-enum-users --script-args krb5-enum-users.realm='<DOMAIN>' $TARGET" ;;
        ldap*)
            KNOWN_SERVICE=true
            RECOMMENDATION="ldapsearch -x -H ldap://$TARGET:$PORT -s base namingcontexts" ;;
        microsoft-ds|smb|netbios-ssn)
            KNOWN_SERVICE=true
            RECOMMENDATION="enum4linux-ng -A $TARGET" ;;
        ms-sql-s)
            KNOWN_SERVICE=true
            RECOMMENDATION="impacket-mssqlclient -windows-auth <DOMAIN>/<USER>@$TARGET" ;;
        nfs)
            KNOWN_SERVICE=true
            RECOMMENDATION="showmount -e $TARGET" ;;
        mysql|mariadb)
            KNOWN_SERVICE=true
            RECOMMENDATION="mysql -h $TARGET -P $PORT -u root" ;;
        postgresql)
            KNOWN_SERVICE=true
            RECOMMENDATION="psql -h $TARGET -p $PORT -U postgres" ;;
        ms-wbt-server)
            KNOWN_SERVICE=true
            RECOMMENDATION="nmap -p $PORT --script rdp-ntlm-info $TARGET" ;;
        winrm)
            KNOWN_SERVICE=true
            RECOMMENDATION="crackmapexec winrm $TARGET -u 'guest' -p ''" ;;
        rsync)
            KNOWN_SERVICE=true
            RECOMMENDATION="rsync --list-only $TARGET::" ;;
        redis)
            KNOWN_SERVICE=true
            RECOMMENDATION="redis-cli -h $TARGET -p $PORT info" ;;
        mongodb)
            KNOWN_SERVICE=true
            RECOMMENDATION="mongo --host $TARGET --port $PORT" ;;
        elasticsearch)
            KNOWN_SERVICE=true
            RECOMMENDATION="curl -X GET 'http://$TARGET:$PORT/_cat/indices?v'" ;;
    esac

    # --- 3. FINAL TRIAGE OUTPUT ---
    if [ "$KNOWN_PORT" = true ] && [ "$KNOWN_SERVICE" = true ]; then
        echo -e "${GREEN}$PORT\t$STATE\t$SERVICE_DET\t\t[MATCH]${NC}"
        echo -e "  ${YELLOW}>> Run: ${NC}$RECOMMENDATION"
    elif [ "$KNOWN_PORT" = false ] && [ "$KNOWN_SERVICE" = true ]; then
        echo -e "${YELLOW}$PORT\t$STATE\t$SERVICE_DET\t\t[MISMATCH]${NC}"
        echo -e "  ${YELLOW}>> Run (Service Identified): ${NC}$RECOMMENDATION"
    elif [ "$KNOWN_PORT" = true ] && [ "$KNOWN_SERVICE" = false ]; then
        echo -e "${ORANGE}$PORT\t$STATE\t$SERVICE_DET\t\t[SERVICE UNKNOWN]${NC}"
    else
        echo -e "${RED}$PORT\t$STATE\t$SERVICE_DET\t\t[UNKNOWN TARGET]${NC}"
    fi
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
