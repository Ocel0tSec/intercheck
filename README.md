# intercheck
Python tool to check popular ssrf CVE's using interact.sh<br/> 
<br/> 
Usage:<br/> 
python3 intercheck.py -l targets.txt -sh your-interact-endpoint -o results.txt<br/> 
python3 intercheck.py -t target-hostname -sh your-interact-endpoint -o results.txt<br/> 
<br/> 
Options:<br/> 
-l, --list        File containing list of IPs/hostnames<br/> 
-t, --target      Single hostname/IP<br/> 
-sh, --interact   Interact.sh endpoint (required)<br/> 
-o, --output      Output file (default: output.txt)<br/> 
-h, --help        Show this help message and exit<br/> 
<br/> 
Use the cli version of interact.sh to get an endpoint or use the webapp https://app.interactsh.com/#/<br/> 
![image](https://github.com/Ocel0tSec/intercheck/assets/78559938/e5061b57-fc5e-4df7-9b77-944cd3e3b840)
