---
name: W_RECON
description: Comprehensive attack surface discovery and reconnaissance
trigger: Standalone recon request or first phase of any hunt
agents: [ReconAgent, SubdomainTakeoverAgent, SecretsExposureAgent, ValidatorAgent, ExploitChainAgent]
tools: [dev-browser, burp-bridge]
skills_invoked: [Recon, OSINT]
---

# W_RECON — Standalone Reconnaissance Workflow

## Overview

Comprehensive attack surface discovery and reconnaissance workflow for bug bounty and penetration testing engagements. This workflow systematically maps the target's external footprint through passive and active techniques, enumerating subdomains, live hosts, content, technologies, and potential takeover vectors.

---

## Phase 1: PASSIVE RECON

**Objective:** Gather intelligence without directly interacting with target infrastructure.

### WHOIS and Domain Intelligence

```bash
# WHOIS lookup for domain registration details
whois target.com
whois -h whois.arin.net "n target.com"

# Reverse WHOIS by registrant email/org
# Use ViewDNS.info, DomainTools, or SecurityTrails API
curl -s "https://api.securitytrails.com/v1/domain/target.com" \
  -H "APIKEY: <ST_API_KEY>" | jq

# Historical WHOIS records
curl -s "https://api.securitytrails.com/v1/domain/target.com/whois" \
  -H "APIKEY: <ST_API_KEY>" | jq
```

### DNS Record Enumeration

```bash
# Comprehensive DNS record query
dig target.com ANY +noall +answer
dig target.com A AAAA CNAME MX NS TXT SOA +noall +answer
dig @8.8.8.8 target.com AXFR  # Zone transfer attempt

# DNS over HTTPS for stealth
curl -s "https://dns.google/resolve?name=target.com&type=ANY" | jq

# Reverse DNS on discovered IPs
for ip in $(dig +short target.com); do dig -x $ip +short; done

# SPF, DKIM, DMARC records
dig target.com TXT +short | grep -i spf
dig _dmarc.target.com TXT +short
dig default._domainkey.target.com TXT +short

# DNSSEC analysis
dig target.com DNSKEY +dnssec
```

### Certificate Transparency

```bash
# crt.sh query for subdomains
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value' | sort -u

# Alternative CT log queries
curl -s "https://certspotter.com/api/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq '.[].dns_names[]' | sort -u

# Censys certificate search
censys search "parsed.names: target.com" --index-type certificates
```

### Shodan and Censys

```bash
# Shodan host search
shodan search "hostname:target.com" --fields ip_str,port,org,product
shodan search "ssl.cert.subject.cn:target.com"
shodan host <IP>

# Censys host search
censys search "services.tls.certificates.leaf.names: target.com"
censys view <IP>

# Shodan domain info
shodan domain target.com
shodan stats --facets port "hostname:target.com"
```

### SecurityTrails API

```bash
# Subdomains via SecurityTrails
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: <ST_API_KEY>" | jq '.subdomains[]'

# DNS history
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
  -H "APIKEY: <ST_API_KEY>" | jq

# Associated domains (same registrant, IP, NS)
curl -s "https://api.securitytrails.com/v1/domain/target.com/associated" \
  -H "APIKEY: <ST_API_KEY>" | jq
```

### Wayback Machine and Archive

```bash
# Wayback Machine URL listing
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original&collapse=urlkey" | jq '.[1:][] | .[0]' | sort -u

# Check for archived sensitive pages
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/admin*&output=text&fl=original,timestamp" | sort -u

# BuiltWith technology lookup
curl -s "https://api.builtwith.com/v19/api.json?KEY=<API_KEY>&LOOKUP=target.com" | jq
```

---

## Phase 2: SUBDOMAIN ENUMERATION

**Objective:** Discover all subdomains through multiple data sources and DNS brute-forcing.

### Passive Subdomain Enumeration

```bash
# subfinder — multi-source passive subdomain discovery
subfinder -d target.com -all -o subs_subfinder.txt
subfinder -d target.com -all -recursive -o subs_subfinder_recursive.txt

# amass passive enumeration
amass enum -passive -d target.com -o subs_amass_passive.txt
amass enum -passive -d target.com -src -o subs_amass_sourced.txt

# assetfinder
assetfinder --subs-only target.com | tee subs_assetfinder.txt

# findomain
findomain -t target.com -u subs_findomain.txt

# chaos (ProjectDiscovery)
chaos -d target.com -o subs_chaos.txt
```

### Active Subdomain Enumeration

```bash
# amass active enumeration with brute-force
amass enum -active -brute -d target.com -o subs_amass_active.txt -rf resolvers.txt
amass enum -active -brute -d target.com -w /usr/share/wordlists/subdomains-top1million-110000.txt -o subs_brute.txt

# DNS brute-force with puredns
puredns bruteforce /usr/share/wordlists/subdomains-top1million-110000.txt target.com -r resolvers.txt -w subs_puredns.txt

# Resolve discovered subdomains
puredns resolve all_subs_merged.txt -r resolvers.txt -w subs_resolved.txt
```

### Permutation Scanning

```bash
# dnsgen — generate subdomain permutations
cat subs_resolved.txt | dnsgen - | puredns resolve -r resolvers.txt -w subs_permutations.txt

# gotator — advanced permutation
gotator -sub subs_resolved.txt -perm permutations.txt -depth 1 -numbers 3 -md | puredns resolve -r resolvers.txt -w subs_gotator.txt

# altdns
altdns -i subs_resolved.txt -o altdns_output.txt -w words.txt -r -s altdns_resolved.txt
```

### Merge and Deduplicate

```bash
# Combine all subdomain sources
cat subs_subfinder.txt subs_amass_passive.txt subs_assetfinder.txt subs_findomain.txt subs_chaos.txt subs_amass_active.txt subs_puredns.txt subs_permutations.txt subs_gotator.txt 2>/dev/null | sort -u > all_subdomains.txt

echo "[*] Total unique subdomains: $(wc -l < all_subdomains.txt)"
```

---

## Phase 3: LIVE HOST DISCOVERY

**Objective:** Identify live web servers, open ports, and capture screenshots of the attack surface.

### HTTP Probing

```bash
# httpx — probe for live HTTP/HTTPS services
httpx -l all_subdomains.txt -o live_hosts.txt -status-code -content-length -title -tech-detect -follow-redirects
httpx -l all_subdomains.txt -o live_hosts_full.txt -status-code -content-length -title -tech-detect -web-server -cdn -ip -cname -follow-redirects -threads 50

# Filter by status code
httpx -l all_subdomains.txt -mc 200,301,302,403 -o live_200_301_302_403.txt

# Check for specific response patterns
httpx -l all_subdomains.txt -match-string "login\|admin\|dashboard" -o interesting_hosts.txt
```

### Virtual Host Discovery

```bash
# vhost brute-force with ffuf
ffuf -u https://<TARGET_IP> -H "Host: FUZZ.target.com" -w /usr/share/wordlists/subdomains-top1million-5000.txt -fs <DEFAULT_SIZE>

# gobuster vhost mode
gobuster vhost -u https://target.com -w /usr/share/wordlists/subdomains-top1million-5000.txt --append-domain -t 50
```

### Port Scanning

```bash
# naabu — fast port scanner
naabu -l all_subdomains.txt -top-ports 1000 -o ports.txt
naabu -l all_subdomains.txt -p - -o all_ports.txt  # Full port scan
naabu -host target.com -p 80,443,8080,8443,8000,3000,5000,9090 -o web_ports.txt

# nmap service detection on discovered ports
nmap -sV -sC -iL live_ips.txt -oA nmap_results
nmap -sV --script=http-enum,http-headers,http-methods -p 80,443,8080 -iL live_ips.txt -oA nmap_http
```

### Screenshot Gallery

```bash
# gowitness — screenshot web pages
gowitness scan file -f live_hosts.txt --threads 10
gowitness report serve  # View screenshot gallery

# aquatone alternative
cat live_hosts.txt | aquatone -out aquatone_results -threads 5 -screenshot-timeout 30000

# eyewitness
eyewitness --web -f live_hosts.txt --timeout 30 -d eyewitness_output
```

---

## Phase 4: CONTENT DISCOVERY

**Objective:** Scrape URLs, discover parameters, and brute-force directories.

### URL Scraping

```bash
# waybackurls — fetch URLs from Wayback Machine
cat all_subdomains.txt | waybackurls | tee wayback_urls.txt

# gau — get all URLs from multiple sources
cat all_subdomains.txt | gau --threads 5 --o gau_urls.txt

# katana — crawling and spidering
katana -list live_hosts.txt -d 5 -jc -kf all -o katana_urls.txt
katana -u https://target.com -d 5 -jc -kf all -aff -o katana_deep.txt

# hakrawler
cat live_hosts.txt | hakrawler -d 3 -insecure | tee hakrawler_urls.txt

# Merge and filter URLs
cat wayback_urls.txt gau_urls.txt katana_urls.txt hakrawler_urls.txt | sort -u > all_urls.txt
cat all_urls.txt | grep -iE "\.(php|asp|aspx|jsp|json|xml|cfg|conf|env|bak|old|sql|log|txt)$" > interesting_urls.txt
```

### Parameter Mining

```bash
# paramspider — parameter discovery from web archives
paramspider -d target.com -o params_spider.txt

# arjun — hidden parameter discovery
arjun -u https://target.com/api/endpoint -m GET POST -o arjun_params.json
arjun -i live_hosts.txt -oJ arjun_bulk.json

# x8 — hidden parameter brute-force
x8 -u https://target.com/page -w params.txt -o x8_params.txt

# Extract unique parameters from all URLs
cat all_urls.txt | grep "?" | unfurl --unique keys | sort -u > all_parameters.txt
```

### Directory Brute-force

```bash
# ffuf — fast directory/file brute-force
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200,301,302,403 -o ffuf_dirs.json -of json
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc all -fc 404 -ac -t 100

# ffuf with extensions
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.asp,.aspx,.jsp,.html,.js,.json,.xml,.bak,.old,.txt,.cfg,.env -mc 200,301,302,403 -o ffuf_files.json

# dirsearch
dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js -t 50 --format json -o dirsearch_results.json

# feroxbuster — recursive content discovery
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,js -t 50 --smart -o ferox_results.txt
```

---

## Phase 5: JAVASCRIPT ANALYSIS

**Objective:** Extract endpoints, secrets, and sensitive data from JavaScript files.

### JS File Collection

```bash
# Extract JS file URLs
cat all_urls.txt | grep -iE "\.js(\?|$)" | sort -u > js_files.txt

# Download all JS files
mkdir -p js_downloads
while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -sk "$url" -o "js_downloads/$filename" 2>/dev/null
done < js_files.txt

# katana JS-focused crawl
katana -u https://target.com -jc -d 3 -ef css,png,jpg,gif,svg,woff -o katana_js_urls.txt
```

### Endpoint and Secret Extraction

```bash
# linkfinder — extract endpoints from JS
python3 linkfinder.py -i https://target.com -d -o cli | tee linkfinder_endpoints.txt
for js in $(cat js_files.txt); do
  python3 linkfinder.py -i "$js" -o cli >> linkfinder_all.txt 2>/dev/null
done

# secretfinder — extract secrets from JS
python3 SecretFinder.py -i https://target.com -e -o cli | tee secretfinder_results.txt

# nuclei JS exposure templates
nuclei -l js_files.txt -t exposures/ -o nuclei_js_exposure.txt

# Manual regex-based extraction
grep -rhoP "(api|secret|token|key|password|auth|access)[_-]?[a-zA-Z]*\s*[:=]\s*['\"][^'\"]{8,}['\"]" js_downloads/ | sort -u > js_secrets.txt

# API endpoint extraction
grep -rhoP "(https?://[^\s'\"<>]+|/api/[^\s'\"<>]+|/v[0-9]+/[^\s'\"<>]+)" js_downloads/ | sort -u > js_api_endpoints.txt

# AWS keys in JS
grep -rhoP "AKIA[0-9A-Z]{16}" js_downloads/ > js_aws_keys.txt

# Google Maps API keys
grep -rhoP "AIza[0-9A-Za-z_-]{35}" js_downloads/ > js_google_keys.txt
```

### JS Beautification and Analysis

```bash
# Beautify minified JS for manual review
for f in js_downloads/*.js; do
  js-beautify "$f" -o "${f%.js}_beautified.js" 2>/dev/null
done

# Search for dangerous functions
grep -rn "eval(\|innerHTML\|document\.write\|\.exec(\|child_process\|dangerouslySetInnerHTML" js_downloads/ > js_dangerous_functions.txt
```

---

## Phase 6: TECHNOLOGY FINGERPRINTING

**Objective:** Identify web technologies, frameworks, CMS platforms, and server software.

### Technology Detection

```bash
# whatweb — web technology fingerprinting
whatweb -i live_hosts.txt --log-json whatweb_results.json -a 3
whatweb target.com -v

# httpx built-in tech detection
httpx -l live_hosts.txt -tech-detect -json -o httpx_tech.json

# webanalyze (Wappalyzer CLI)
webanalyze -hosts live_hosts.txt -output json > webanalyze_results.json

# nuclei technology detection
nuclei -l live_hosts.txt -t technologies/ -o nuclei_tech.txt
```

### CMS Identification

```bash
# CMSeeK — CMS detection and exploitation
python3 cmseek.py -u https://target.com

# wpscan (WordPress)
wpscan --url https://target.com --enumerate u,vp,vt,dbe --api-token <WP_API_TOKEN> -o wpscan_results.json -f json

# joomscan (Joomla)
joomscan -u https://target.com

# droopescan (Drupal/Silverstripe/WordPress)
droopescan scan drupal -u https://target.com
```

### Server and Framework Detection

```bash
# HTTP header analysis
curl -sI https://target.com | grep -iE "server:|x-powered-by:|x-aspnet-version:|x-generator:|x-drupal"

# Error page fingerprinting
curl -sk https://target.com/nonexistent_page_12345 -o error_page.html

# robots.txt and sitemap analysis
curl -sk https://target.com/robots.txt | tee robots.txt
curl -sk https://target.com/sitemap.xml | tee sitemap.xml

# Common framework paths
for path in /wp-login.php /wp-admin /administrator /user/login /elmah.axd /_profiler /actuator /swagger-ui.html /graphql; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com${path}")
  echo "${path}: ${code}"
done
```

---

## Phase 7: SUBDOMAIN TAKEOVER CHECK

**Objective:** Identify dangling DNS records vulnerable to subdomain takeover.

### Automated Takeover Scanning

```bash
# subjack — subdomain takeover tool
subjack -w all_subdomains.txt -t 100 -timeout 30 -o subjack_results.txt -ssl -v

# nuclei takeover templates
nuclei -l all_subdomains.txt -t takeovers/ -o nuclei_takeover.txt

# subzy
subzy run --targets all_subdomains.txt --output subzy_results.txt

# can-i-take-over-xyz reference check
# https://github.com/EdOverflow/can-i-take-over-xyz
```

### Dangling DNS Identification

```bash
# Check CNAME records pointing to decommissioned services
for sub in $(cat all_subdomains.txt); do
  cname=$(dig +short CNAME "$sub" 2>/dev/null)
  if [ -n "$cname" ]; then
    # Check if CNAME target resolves
    resolved=$(dig +short "$cname" 2>/dev/null)
    if [ -z "$resolved" ]; then
      echo "[DANGLING] $sub -> $cname (NXDOMAIN)"
    fi
  fi
done | tee dangling_cnames.txt

# Check for common takeover-vulnerable CNAME patterns
grep -iE "(s3\.amazonaws|herokuapp|ghost\.io|pantheon\.io|readme\.io|surge\.sh|bitbucket\.io|wordpress\.com|shopify\.com|fastly|cloudfront|azurewebsites|trafficmanager|blob\.core)" dangling_cnames.txt > potential_takeovers.txt
```

### NS Takeover Check

```bash
# Check for NS records pointing to expired/available domains
for sub in $(cat all_subdomains.txt); do
  ns_records=$(dig +short NS "$sub" 2>/dev/null)
  for ns in $ns_records; do
    whois "$ns" 2>/dev/null | grep -qi "no match\|not found\|available" && echo "[NS-TAKEOVER] $sub -> $ns"
  done
done | tee ns_takeover.txt
```

---

## Phase 8: GOOGLE DORKING

**Objective:** Discover sensitive information, admin panels, exposed files, and error pages via search engine queries.

### Site-Specific Dorks

```bash
# Core dorks (use in browser or via Google Custom Search API)
# site:target.com inurl:admin
# site:target.com inurl:login
# site:target.com inurl:dashboard
# site:target.com inurl:api
# site:target.com intitle:"index of"
# site:target.com ext:php inurl:?
# site:target.com inurl:config
# site:target.com inurl:backup
```

### Filetype Searches

```bash
# Sensitive file discovery
# site:target.com ext:sql
# site:target.com ext:log
# site:target.com ext:bak
# site:target.com ext:env
# site:target.com ext:cfg
# site:target.com ext:conf
# site:target.com ext:xml
# site:target.com ext:json
# site:target.com ext:csv
# site:target.com filetype:pdf confidential
# site:target.com filetype:xlsx password
# site:target.com filetype:doc internal
```

### Error Page and Debug Discovery

```bash
# Error page dorks
# site:target.com "fatal error"
# site:target.com "stack trace"
# site:target.com "SQL syntax"
# site:target.com "Warning: mysql"
# site:target.com "Parse error"
# site:target.com "Debug" inurl:debug
# site:target.com inurl:trace.axd
# site:target.com "phpinfo()"
# site:target.com "server at" intitle:index
```

### Admin Panel Discovery

```bash
# Admin/management panels
# site:target.com inurl:/admin
# site:target.com inurl:wp-admin
# site:target.com inurl:cpanel
# site:target.com inurl:phpmyadmin
# site:target.com inurl:jenkins
# site:target.com inurl:grafana
# site:target.com inurl:kibana
# site:target.com intitle:"Swagger UI"
# site:target.com intitle:"GraphQL Playground"
```

---

## Phase 9: GITHUB/SOURCE RECON

**Objective:** Discover leaked credentials, API keys, internal code, and sensitive data in public repositories.

### GitHub Dorking

```bash
# trufflehog — find secrets in git repos
trufflehog github --org <TARGET_ORG> --json | tee trufflehog_results.json
trufflehog git https://github.com/<ORG>/<REPO>.git --json | tee trufflehog_repo.json

# gitdorker
python3 gitdorker.py -t <GITHUB_TOKEN> -d dorks/alldorks.txt -q target.com -o gitdorker_results.txt

# gitleaks
gitleaks detect --source /path/to/cloned/repo --report-format json --report-path gitleaks_results.json

# Manual GitHub search queries
# "target.com" password
# "target.com" api_key
# "target.com" secret
# org:target-org filename:.env
# org:target-org filename:config
# org:target-org extension:pem
# org:target-org extension:key
# org:target-org "BEGIN RSA PRIVATE KEY"
# org:target-org AWS_ACCESS_KEY_ID
# org:target-org jdbc:mysql://
```

### GitHub API Enumeration

```bash
# List organization repos
curl -s -H "Authorization: token <TOKEN>" "https://api.github.com/orgs/<ORG>/repos?per_page=100&type=all" | jq '.[].full_name'

# List organization members
curl -s -H "Authorization: token <TOKEN>" "https://api.github.com/orgs/<ORG>/members" | jq '.[].login'

# Search code in repos
curl -s -H "Authorization: token <TOKEN>" "https://api.github.com/search/code?q=org:<ORG>+password+filename:.env" | jq '.items[] | {repo: .repository.full_name, path: .path}'

# Check for GitHub Actions secrets leakage
curl -s -H "Authorization: token <TOKEN>" "https://api.github.com/repos/<ORG>/<REPO>/actions/workflows" | jq
```

### Other Source Platforms

```bash
# GitLab search
# https://gitlab.com/search?search=target.com&scope=blobs

# Bitbucket search
# https://bitbucket.org/search?q=target.com

# Pastebin / paste site search
# https://psbdmp.ws/api/search/target.com

# Postman API collections
# https://www.postman.com/search?q=target.com
```

---

## Phase 10: REPORTING

**Objective:** Compile the attack surface map, generate prioritized target lists, and document all findings.

### Attack Surface Compilation

```bash
# Generate summary statistics
echo "=== RECON SUMMARY ==="
echo "Subdomains discovered: $(wc -l < all_subdomains.txt)"
echo "Live hosts: $(wc -l < live_hosts.txt)"
echo "Unique URLs: $(wc -l < all_urls.txt)"
echo "JS files found: $(wc -l < js_files.txt)"
echo "Parameters discovered: $(wc -l < all_parameters.txt)"
echo "Potential takeovers: $(wc -l < potential_takeovers.txt 2>/dev/null || echo 0)"
echo "Secrets found: $(wc -l < js_secrets.txt 2>/dev/null || echo 0)"
```

### Prioritized Target List

```bash
# High-priority targets (admin panels, APIs, login pages)
cat live_hosts_full.txt | grep -iE "admin|api|login|dashboard|portal|staging|dev|test|internal|jenkins|grafana|kibana|swagger" > high_priority_targets.txt

# Identify unique tech stacks for targeted testing
cat httpx_tech.json | jq -r '.technologies[]' 2>/dev/null | sort | uniq -c | sort -rn > tech_stack_summary.txt

# Generate target-specific nuclei scan
nuclei -l live_hosts.txt -severity critical,high -o nuclei_critical_high.txt
```

### Output Directory Structure

```
recon_output/
├── subdomains/
│   ├── all_subdomains.txt
│   ├── subs_resolved.txt
│   └── dangling_cnames.txt
├── hosts/
│   ├── live_hosts.txt
│   ├── ports.txt
│   └── screenshots/
├── urls/
│   ├── all_urls.txt
│   ├── interesting_urls.txt
│   └── js_files.txt
├── secrets/
│   ├── js_secrets.txt
│   ├── trufflehog_results.json
│   └── gitleaks_results.json
├── technology/
│   ├── whatweb_results.json
│   └── tech_stack_summary.txt
├── takeover/
│   ├── potential_takeovers.txt
│   └── ns_takeover.txt
└── reports/
    ├── high_priority_targets.txt
    ├── nuclei_critical_high.txt
    └── recon_summary.txt
```

---

## Decision Gates

| Gate | Condition | Action |
|------|-----------|--------|
| Post-Passive | No domain records found | Verify target scope, re-check |
| Post-Subdomain | < 5 subdomains | Increase brute-force depth, check wildcard DNS |
| Post-Probe | No live hosts | Verify connectivity, check WAF blocking |
| Post-Content | No interesting URLs | Deeper crawl, check JS files |
| Post-Takeover | Takeover found | Document, verify, report immediately |
| Post-GitHub | Credentials found | Validate, document, report immediately |
| Wildcard DNS | Wildcard detected | Filter false positives, use response comparison |

## Tool Reference

| Tool | Purpose | Install |
|------|---------|---------|
| subfinder | Passive subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| amass | Attack surface mapping | `go install github.com/owasp-amass/amass/v4/...@master` |
| httpx | HTTP probing and tech detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| naabu | Fast port scanner | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| katana | Web crawler/spider | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| nuclei | Vulnerability scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| ffuf | Web fuzzer | `go install github.com/ffuf/ffuf/v2@latest` |
| gowitness | Screenshot tool | `go install github.com/sensepost/gowitness@latest` |
| trufflehog | Secret scanner | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| waybackurls | Wayback URL fetcher | `go install github.com/tomnomnom/waybackurls@latest` |
| gau | URL aggregator | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| puredns | DNS resolution/brute-force | `go install github.com/d3mondev/puredns/v2@latest` |
