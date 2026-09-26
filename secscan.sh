#!/bin/bash 

if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: $0 <Target_IP>"
    echo "Example: $0 192.168.1.10"
    exit 0
elif [ "$1" == "--version" ] || [ "$1" == "-v" ]; then
    echo "SecScan Security Assessment Tool v1.0"
    exit 0
fi

TARGET="$1"
REPORTS_DIR="reports"
SCAN_FILE="$REPORTS_DIR/scan.txt"
FINDINGS_FILE="$REPORTS_DIR/findings.txt"
SUMMARY_FILE="$REPORTS_DIR/summary.txt"

if [ -z "$TARGET" ]; then
    echo -e "\033[31m[-] Error: No Target Provided!\033[0m"
    echo "Usage: $0 <Target_IP>"
    exit 1 
fi

if ! command -v nmap &> /dev/null; then
    echo -e "\033[31m[-] Error: nmap is not installed.\033[0m"
    exit 1
fi

mkdir -p "$REPORTS_DIR"
> "$FINDINGS_FILE"

echo -e "\033[34m[*] Stage 1: Checking target availability ($TARGET)...\033[0m"

if ping -c 2 "$TARGET" &> /dev/null; then
    echo -e "\033[32m[+] Target $TARGET is UP!\033[0m"
else
    echo -e "\033[31m[-] Error: Target $TARGET is unreachable!\033[0m"
    exit 1
fi  

echo -e "\033[34m[*] Stage 2: Scanning open ports and services...\033[0m"

nmap -sV -F "$TARGET" > "$SCAN_FILE"
if [ -s "$SCAN_FILE" ]; then
    echo -e "\033[32m[+] Scan completed. Raw scan results saved to $SCAN_FILE\033[0m"
else
    echo -e "\033[31m[-] Error: Nmap scan failed or returned no results.\033[0m"
    exit 1
fi

echo -e "\033[33m[+] Open Ports & Services Found:\033[0m"
grep "open" "$SCAN_FILE"
echo ""


check_ftp() {
    local port=$1
    echo -e "\033[34m[*] Running FTP enumeration on port $port...\033[0m"
    
    local ftp_res=$(nmap --script ftp-anon -p "$port" "$TARGET" 2>/dev/null)
    if echo "$ftp_res" | grep -q "Anonymous FTP login allowed"; then
        echo -e "\033[31m[!] Finding: Anonymous FTP Login Allowed\033[0m"
        echo "[+] [FTP Port $port] Anonymous login allowed!" >> "$FINDINGS_FILE"
        echo "    Evidence: Successfully authenticated as 'anonymous'" >> "$FINDINGS_FILE"
        echo "    Risk: High - Unauthorized users can access or modify files." >> "$FINDINGS_FILE"
        echo "    Recommendation: Disable anonymous login in FTP server configuration." >> "$FINDINGS_FILE"
        echo "" >> "$FINDINGS_FILE"
    else
        echo -e "\033[32m[+] FTP Anonymous login is disabled or not accessible.\033[0m"
    fi
}

check_ssh() {
    local port=$1
    echo -e "\033[34m[*] Running SSH banner check on port $port...\033[0m"
    
    local ssh_banner=$(grep "$port/tcp" "$SCAN_FILE")
    echo -e "\033[32m[+] SSH Banner: $ssh_banner\033[0m"
    
    echo "[+] [SSH Port $port] Service Banner Collected" >> "$FINDINGS_FILE"
    echo "    Evidence: $ssh_banner" >> "$FINDINGS_FILE"
    echo "    Risk: Low - Discloses service version details." >> "$FINDINGS_FILE"
    echo "    Recommendation: Restrict access via firewall and keep SSH updated." >> "$FINDINGS_FILE"
    echo "" >> "$FINDINGS_FILE"
}

check_http() {
    local port=$1
    echo -e "\033[34m[*] Running HTTP enumeration on port $port...\033[0m"
    
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET:$port/")
    echo -e "\033[32m[+] HTTP Status Code: $http_code\033[0m"
    
    local robots_status=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET:$port/robots.txt")
    
    echo "[+] [HTTP Port $port] Web Server Detected (HTTP Status: $http_code)" >> "$FINDINGS_FILE"
    if [ "$robots_status" -eq 200 ]; then
        local robots=$(curl -s "http://$TARGET:$port/robots.txt" | head -n 5)
        echo "    Evidence: Found robots.txt content:" >> "$FINDINGS_FILE"
        echo "$robots" | sed 's/^/      /' >> "$FINDINGS_FILE"
    else
        echo "    Evidence: HTTP service active with response code $http_code (robots.txt not found)" >> "$FINDINGS_FILE"
    fi
    echo "    Risk: Medium - Exposed web application endpoints." >> "$FINDINGS_FILE"
    echo "    Recommendation: Audit web application for vulnerabilities and secure endpoints." >> "$FINDINGS_FILE"
    echo "" >> "$FINDINGS_FILE"
}

check_smb() {
    local port=$1
    echo -e "\033[34m[*] Running SMB share enumeration on port $port...\033[0m"
    
    local smb_shares=$(nmap --script smb-enum-shares -p "$port" "$TARGET" 2>/dev/null | grep "Anonymous" -A 2)
    
    echo "[+] [SMB Port $port] Samba Service Detected" >> "$FINDINGS_FILE"
    if [ -n "$smb_shares" ]; then
        echo "    Evidence: SMB Share Info:" >> "$FINDINGS_FILE"
        echo "$smb_shares" | sed 's/^/      /' >> "$FINDINGS_FILE"
    else
        echo "    Evidence: SMB service active on port $port" >> "$FINDINGS_FILE"
    fi
    echo "    Risk: High - SMB misconfigurations can lead to unauthorized share access." >> "$FINDINGS_FILE"
    echo "    Recommendation: Disable guest access and restrict SMB permissions." >> "$FINDINGS_FILE"
    echo "" >> "$FINDINGS_FILE"
}

check_smtp() {
    local port=$1
    echo -e "\033[34m[*] Running SMTP enumeration on port $port...\033[0m"
    
    echo "[+] [SMTP Port $port] Mail Service Detected" >> "$FINDINGS_FILE"
    echo "    Evidence: SMTP service active on port $port" >> "$FINDINGS_FILE"
    echo "    Risk: Medium - Potential user enumeration or open relay." >> "$FINDINGS_FILE"
    echo "    Recommendation: Disable VRFY/EXPN commands and configure proper relay rules." >> "$FINDINGS_FILE"
    echo "" >> "$FINDINGS_FILE"
}

check_dns() {
    local port=$1
    echo -e "\033[34m[*] Running DNS enumeration on port $port...\033[0m"
    
    echo "[+] [DNS Port $port] Domain Service Detected" >> "$FINDINGS_FILE"
    echo "    Evidence: DNS Service responding on port $port" >> "$FINDINGS_FILE"
    echo "    Risk: Low - Discloses internal domain information if zone transfer is enabled." >> "$FINDINGS_FILE"
    echo "    Recommendation: Restrict zone transfers (AXFR) to authorized secondary DNS servers." >> "$FINDINGS_FILE"
    echo "" >> "$FINDINGS_FILE"
}

echo -e "\033[34m[*] Stage 3: Starting Automated Service Enumeration...\033[0m"

grep "open" "$SCAN_FILE" | while read -r line; do
    PORT=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
    SERVICE=$(echo "$line" | awk '{print $3}')

    case "$SERVICE" in
        ftp)
            check_ftp "$PORT"
            ;;
        ssh)
            check_ssh "$PORT"
            ;;
        http|http*)
            check_http "$PORT"
            ;;
        netbios-ssn|microsoft-ds|smb)
            check_smb "$PORT"
            ;;
        smtp)
            check_smtp "$PORT"
            ;;
        domain|dns)
            check_dns "$PORT"
            ;;
        *)
            echo -e "\033[33m[*] Service '$SERVICE' on port $PORT detected (No specific auto-check module).\033[0m"
            ;;
    esac
done

echo -e "\033[34m[*] Stage 4: Generating Structured Reports...\033[0m"

{
    echo "=========================================="
    echo "        SECURITY ASSESSMENT REPORT        "
    echo "=========================================="
    echo "Target IP   : $TARGET"
    echo "Scan Date   : $(date)"
    echo "=========================================="
    echo ""
    echo "--- Open Services Summary ---"
    grep "open" "$SCAN_FILE"
    echo ""
    echo "=========================================="
    echo "Detailed findings are stored in: $FINDINGS_FILE"
    echo "=========================================="
} > "$SUMMARY_FILE"

echo -e "\033[32m[+] Assessment Complete!\033[0m"
echo -e "\033[32m[+] Summary Report : $SUMMARY_FILE\033[0m"
echo -e "\033[32m[+] Detailed Findings: $FINDINGS_FILE\033[0m"
