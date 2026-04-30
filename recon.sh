#!/bin/bash

# --- PHASE 0: IMMEDIATE LOGGING SETUP ---
# Start capturing everything immediately into a temp file
TEMP_LOG="/tmp/recon_init.log"
exec > >(tee -a "$TEMP_LOG") 2>&1

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

# Check for ansi2html and install if missing
if ! command -v ansi2html &> /dev/null; then
    echo -e "${YELLOW}[!] ansi2html not found. Attempting to install...${NC}"
    sudo apt update && sudo apt install -y colorized-logs
    if [ $? -ne 0 ]; then
        echo -e "${RED}[- ] Failed to install colorized-logs. HTML report will be skipped.${NC}"
    fi
fi

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

# --- FINALIZE LOGGING ---
# Move the initial boot logs to the recon folder and resume logging there
FINAL_LOG="$DIR/${PREFIX}console_output.log"
cat "$TEMP_LOG" > "$FINAL_LOG"
rm "$TEMP_LOG"
exec > >(tee -a "$FINAL_LOG") 2>&1

echo -e "${BLUE}${BOLD}[+] Initializing Recon on $NAME ($TARGET)${NC}"
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
        DOMAIN=$(curl -Is --connect-timeout 5 http://$TARGET:$port 2>/dev/null | grep -i '^Location' | awk '{print $2}' | sed 's/http[s]*:\/\///' | cut -d'/' -f1 | tr -d '\r')

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
CMD_DEEP="sudo nmap -sC -sV -p$TCP_PORTS --script=banner,default,vulners -oN $DIR/${PREFIX}tcp_detailed.nmap -oX $DIR/${PREFIX}tcp_detailed.xml -oG $DIR/${PREFIX}tcp_ports_detailed.grep $TARGET"
echo -e "  [Run]: $CMD_DEEP"
$CMD_DEEP > /dev/null

echo -e "\n${MAGENTA}${BOLD}[!] COMPREHENSIVE SERVICE EVALUATION & TRIAGE:${NC}"
echo -e "${CYAN}PORT\tSTATE\tSERVICE\t\tSTATUS & RECOMMENDATION${NC}"
echo -e "${CYAN}------------------------------------------------------------${NC}"

grep -v "^#" "$DIR/${PREFIX}tcp_ports_detailed.grep" | grep "Ports:" | sed 's/.*Ports: //' | tr ',' '\n' | while read -r line; do
    PORT=$(echo $line | cut -d'/' -f1 | xargs)
    STATE=$(echo $line | cut -d'/' -f2 | xargs)
    SERVICE_DET=$(echo $line | cut -d'/' -f5 | xargs)

    IS_KNOWN_PORT=false
    IS_KNOWN_SERVICE=false
    EXPECTED_PORT=""
    RECOMMENDATION=""

    case $SERVICE_DET in
        ftp*)          IS_KNOWN_SERVICE=true; EXPECTED_PORT="21"; RECOMMENDATION="nmap -sV --script ftp-anon -p $PORT $TARGET" ;;
        ssh)           IS_KNOWN_SERVICE=true; EXPECTED_PORT="22"; RECOMMENDATION="ssh -v -o PreferredAuthentications=password $TARGET -p $PORT" ;;
        telnet)        IS_KNOWN_SERVICE=true; EXPECTED_PORT="23"; RECOMMENDATION="telnet $TARGET $PORT" ;;
        smtp|submission|smtps) IS_KNOWN_SERVICE=true; EXPECTED_PORT="25"; RECOMMENDATION="nmap -p $PORT --script smtp-enum-users $TARGET" ;;
        domain)        IS_KNOWN_SERVICE=true; EXPECTED_PORT="53"; RECOMMENDATION="dig axfr @$TARGET \$DOMAIN" ;;
        finger)        IS_KNOWN_SERVICE=true; EXPECTED_PORT="79"; RECOMMENDATION="finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t $TARGET" ;;
        http*|ssl/http*|https*|uwsgi|nginx|apache|jetty|cups)
            IS_KNOWN_SERVICE=true; EXPECTED_PORT="80"
            PROTO=$( [[ "$SERVICE_DET" == *"ssl"* || "$PORT" == "443" || "$PORT" == "8443" ]] && echo "https" || echo "http" )
            URL="$PROTO://$TARGET:$PORT"
            RECOMMENDATION="python3 fuzz.py $URL\n      [Fingerprint]: whatweb -a 3 $URL\n      [Vhosts]: ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -H 'Host: FUZZ.$NAME.htb' -u $URL -fs 0" ;;
        kerberos*)     IS_KNOWN_SERVICE=true; EXPECTED_PORT="88"; RECOMMENDATION="nmap -p $PORT --script krb5-enum-users --script-args krb5-enum-users.realm='<DOMAIN>' $TARGET" ;;
        pop3*)         IS_KNOWN_SERVICE=true; EXPECTED_PORT="110"; RECOMMENDATION="nmap -p $PORT --script pop3-capabilities $TARGET" ;;
        rpcbind|sunrpc)
            IS_KNOWN_SERVICE=true; EXPECTED_PORT="111"
            RECOMMENDATION="rpcinfo -p $TARGET\n      [Enum]: rpcclient -U '' -N $TARGET" ;;
        imap*)         IS_KNOWN_SERVICE=true; EXPECTED_PORT="143"; RECOMMENDATION="nmap -p $PORT --script imap-capabilities $TARGET" ;;
        snmp)
            IS_KNOWN_SERVICE=true; EXPECTED_PORT="161"
            RECOMMENDATION="onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $TARGET\n      [Check]: snmp-check $TARGET -c public" ;;
        ldap*)         IS_KNOWN_SERVICE=true; EXPECTED_PORT="389"; RECOMMENDATION="ldapsearch -x -H ldap://$TARGET:$PORT -s base namingcontexts" ;;
        microsoft-ds|smb*|netbios-ssn)
            IS_KNOWN_SERVICE=true; EXPECTED_PORT="445"
            RECOMMENDATION="enum4linux-ng -A $TARGET\n      [Shares]: smbclient -L //$TARGET/ -N\n      [Permissions]: smbmap -H $TARGET" ;;
        rsync)         IS_KNOWN_SERVICE=true; EXPECTED_PORT="873"; RECOMMENDATION="rsync --list-only $TARGET::" ;;
        ms-sql-s)
            IS_KNOWN_SERVICE=true; EXPECTED_PORT="1433"
            RECOMMENDATION="nmap -p $PORT --script ms-sql-info,ms-sql-ntlm-info $TARGET\n      [Client]: impacket-mssqlclient -windows-auth <DOMAIN>/<USER>@$TARGET" ;;
        oracle)        IS_KNOWN_SERVICE=true; EXPECTED_PORT="1521"; RECOMMENDATION="nmap -p $PORT --script oracle-tns-version $TARGET" ;;
        nfs)           IS_KNOWN_SERVICE=true; EXPECTED_PORT="2049"; RECOMMENDATION="showmount -e $TARGET" ;;
        mysql|mariadb)
            IS_KNOWN_SERVICE=true; EXPECTED_PORT="3306"
            RECOMMENDATION="nmap -p $PORT --script mysql-audit,mysql-databases,mysql-variables $TARGET\n      [Login]: mysql -h $TARGET -P $PORT -u root" ;;
        ms-wbt-server) IS_KNOWN_SERVICE=true; EXPECTED_PORT="3389"; RECOMMENDATION="nmap -p $PORT --script rdp-ntlm-info $TARGET" ;;
        postgresql)    IS_KNOWN_SERVICE=true; EXPECTED_PORT="5432"; RECOMMENDATION="psql -h $TARGET -p $PORT -U postgres" ;;
        vnc)           IS_KNOWN_SERVICE=true; EXPECTED_PORT="5900"; RECOMMENDATION="nmap -sV --script vnc-info -p $PORT $TARGET" ;;
        winrm)         IS_KNOWN_SERVICE=true; EXPECTED_PORT="5985"; RECOMMENDATION="crackmapexec winrm $TARGET -u 'guest' -p ''" ;;
        redis)         IS_KNOWN_SERVICE=true; EXPECTED_PORT="6379"; RECOMMENDATION="redis-cli -h $TARGET -p $PORT info" ;;
        mongodb)       IS_KNOWN_SERVICE=true; EXPECTED_PORT="27017"; RECOMMENDATION="mongo --host $TARGET --port $PORT" ;;
    esac

    case $PORT in
        21|22|23|25|53|79|80|88|110|111|135|139|143|161|389|443|445|465|587|593|631|636|873|993|995|1080|1433|1521|2049|3306|3389|3690|4444|5000|5432|5900|5985|5986|6379|8000|8080|8081|8443|8888|9000|9200|10000|27017)
            IS_KNOWN_PORT=true ;;
    esac

    if [ "$IS_KNOWN_SERVICE" = true ]; then
        if [ "$PORT" == "$EXPECTED_PORT" ] || { [ "$EXPECTED_PORT" == "80" ] && [[ "$PORT" =~ ^(443|8000|8080|8081|8443|8888|9000|10000)$ ]]; }; then
            echo -e "${GREEN}$PORT\t$STATE\t$SERVICE_DET\t\t[GREEN: MATCH]${NC}"
            echo -e "  ${YELLOW}>> Run: ${NC}$RECOMMENDATION"
        elif [ "$IS_KNOWN_PORT" = true ]; then
            echo -e "${YELLOW}$PORT\t$STATE\t$SERVICE_DET\t\t[YELLOW: CONFLICT]${NC}"
            echo -e "  ${YELLOW}>> Run: ${NC}$RECOMMENDATION"
        else
            echo -e "${YELLOW}$PORT\t$STATE\t$SERVICE_DET\t\t[YELLOW: OBFUSCATION]${NC}"
            echo -e "  ${YELLOW}>> Run: ${NC}$RECOMMENDATION"
        fi
    elif [ "$IS_KNOWN_PORT" = true ]; then
        echo -e "${ORANGE}$PORT\t$STATE\t$SERVICE_DET\t\t[ORANGE: SIGNATURE FAIL]${NC}"
    else
        echo -e "${RED}$PORT\t$STATE\t$SERVICE_DET\t\t[RED: UNKNOWN]${NC}"
    fi
done

echo -e "${CYAN}[!] Compiling Exploit Database Leads via XML...${NC}"
searchsploit --nmap "$DIR/${PREFIX}tcp_detailed.xml" --disable-colour > "$DIR/${PREFIX}searchsploit_results.txt" 2>/dev/null

if [ -s "$DIR/${PREFIX}searchsploit_results.txt" ]; then
    echo -e "${RED}[+] Exploits found! Check $DIR/${PREFIX}searchsploit_results.txt${NC}"
else
    echo -e "${GREEN}[-] No direct exploit matches found in Searchsploit.${NC}"
fi

PHASE3_END=$(date +%s)
echo -e "${GREEN}[+] Phase 3 Complete in $((PHASE3_END - PHASE3_START)) seconds.${NC}"

# --- PHASE 4: SMART UDP ---
PHASE4_START=$(date +%s)
echo -e "\n${CYAN}[!] Phase 4: Smart UDP (Top 1000) Starting...${NC}"
sudo nmap -sU --top-ports 1000 -T4 --exclude-ports $TCP_PORTS -oN $DIR/${PREFIX}udp_scan.nmap $TARGET > /dev/null

echo -e "${MAGENTA}${BOLD}[!] UDP SERVICE EVALUATION & TRIAGE:${NC}"
echo -e "${CYAN}PORT\tSTATE\tSERVICE\t\tSTATUS & RECOMMENDATION${NC}"
echo -e "${CYAN}------------------------------------------------------------${NC}"

grep "open" "$DIR/${PREFIX}udp_scan.nmap" | while read -r line; do
    PORT=$(echo $line | awk -F'/' '{print $1}')
    STATE=$(echo $line | awk '{print $2}')
    SERVICE_DET=$(echo $line | awk '{print $3}')
    IS_KNOWN_PORT=false
    IS_KNOWN_SERVICE=false
    EXPECTED_PORT=""
    RECOMMENDATION=""

    case $SERVICE_DET in
        snmp)          IS_KNOWN_SERVICE=true; EXPECTED_PORT="161"; RECOMMENDATION="snmp-check $TARGET -c public" ;;
        tftp)          IS_KNOWN_SERVICE=true; EXPECTED_PORT="69";  RECOMMENDATION="tftp $TARGET -c get <file>" ;;
        isakmp|ipsec*) IS_KNOWN_SERVICE=true; EXPECTED_PORT="500"; RECOMMENDATION="ike-scan -M $TARGET" ;;
        domain)        IS_KNOWN_SERVICE=true; EXPECTED_PORT="53";  RECOMMENDATION="dig axfr @$TARGET \$DOMAIN" ;;
        ntp)           IS_KNOWN_SERVICE=true; EXPECTED_PORT="123"; RECOMMENDATION="nmap -sU -p 123 --script ntp-info $TARGET" ;;
    esac

    case $PORT in
        53|67|68|69|123|161|162|500|4500) IS_KNOWN_PORT=true ;;
    esac

    if [ "$IS_KNOWN_SERVICE" = true ]; then
        if [ "$PORT" == "$EXPECTED_PORT" ]; then
            echo -e "${GREEN}$PORT\t$STATE\t$SERVICE_DET\t\t[GREEN: MATCH]${NC}"
            echo -e "  ${YELLOW}>> Run: ${NC}$RECOMMENDATION"
        else
            echo -e "${YELLOW}$PORT\t$STATE\t$SERVICE_DET\t\t[YELLOW: OBFUSCATION]${NC}"
            echo -e "  ${YELLOW}>> Run: ${NC}$RECOMMENDATION"
        fi
    elif [ "$IS_KNOWN_PORT" = true ]; then
        echo -e "${ORANGE}$PORT\t$STATE\t$SERVICE_DET\t\t[ORANGE: SIGNATURE FAIL]${NC}"
    else
        echo -e "${RED}$PORT\t$STATE\t$SERVICE_DET\t\t[RED: UNKNOWN]${NC}"
    fi
done

PHASE4_END=$(date +%s)
echo -e "${GREEN}[+] Phase 4 Complete in $((PHASE4_END - PHASE4_START)) seconds.${NC}"

# --- FINAL SUMMARY ---
TOTAL_END=$(date +%s)
TOTAL_RUNTIME=$((TOTAL_END - TOTAL_START))

echo -e "\n${BLUE}${BOLD}----------------------------------------------------${NC}"
echo -e "${GREEN}${BOLD}[+] RECON COMPLETE FOR $NAME${NC}"
echo -e "${CYAN}[i] Total Runtime: $TOTAL_RUNTIME seconds${NC}"
echo -e "${CYAN}[i] Final Finish: $(date)${NC}"
echo -e "    - Results Directory: $DIR/"
echo -e "${BLUE}${BOLD}----------------------------------------------------${NC}"

# --- HTML REPORT GENERATION ---
if command -v ansi2html &> /dev/null; then
    echo -e "${YELLOW}[!] Generating Visual HTML Report...${NC}"
    cat "$FINAL_LOG" | ansi2html > "$DIR/${PREFIX}report.html"
    echo -e "${GREEN}[+] Report saved: $DIR/${PREFIX}report.html${NC}"
fi