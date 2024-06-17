# intercheck
Python tool to check popular ssrf CVE's using interact.sh

Usage:
python3 intercheck.py -l targets.txt -sh your-interact-endpoint -o results.txt
python3 intercheck.py -t target-hostname -sh your-interact-endpoint -o results.txt

Options:
-l, --list        File containing list of IPs/hostnames
-t, --target      Single hostname/IP
-sh, --interact   Interact.sh endpoint (required)
-o, --output      Output file (default: output.txt)
-h, --help        Show this help message and exit

Use the cli version of interact.sh to get an endpoint or use the webapp https://app.interactsh.com/#/
![image](https://github.com/Ocel0tSec/intercheck/assets/78559938/e5061b57-fc5e-4df7-9b77-944cd3e3b840)
