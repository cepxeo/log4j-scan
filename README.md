<h1>Fork of log4j-scan</h1>
<h4>The log4j CVE-2021-44228, CVE-2021-45046 vulnerability scanner modified to run against the large multi thousands URL base.</h4>

# Added Features in this Fork

- Threading support.
- Extended WAF bypass payloads.
- Each payload made unique to distinguish which target established connection. First 5 symbols of target's hostname MD5 hash included in the payload.
- Improved logging to handle massive output.
- Added option to run the 'canary' test against known vulnerable endpoint.
- Implemented the pattern blacklist to ignore while parsing the target lists.

# Usage

```python
$ python3 log4j-scan.py -h
[•] CVE-2021-44228 - Apache Log4j RCE Scanner
[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
[•] Fork created by Sergey Egorov.

usage: log4j-scan.py [-h] [-u URL] [-l USEDLIST] [--request-type REQUEST_TYPE] [--headers-file HEADERS_FILE] [--run-all-tests] [--exclude-user-agent-fuzzing]
                     [--wait-time WAIT_TIME] [--waf-bypass] [--dns-callback-provider DNS_CALLBACK_PROVIDER] [--custom-dns-callback-host CUSTOM_DNS_CALLBACK_HOST]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Check a single URL.
  -p PROXY, --proxy PROXY
                        Send requests through proxy. proxy should be specified in the format supported by requests
                        (http[s]://<proxy-ip>:<proxy-port>)
  -l USEDLIST, --list USEDLIST
                        Check a list of URLs.
  --request-type REQUEST_TYPE
                        Request Type: (get, post) - [Default: get].
  --headers-file HEADERS_FILE
                        Headers fuzzing list - [default: headers.txt].
  --run-all-tests       Run all available tests on each URL.
  --exclude-user-agent-fuzzing
                        Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.
  --wait-time WAIT_TIME
                        Wait time after all URLs are processed (in seconds) - [Default: 5].
  --waf-bypass          Extend scans with WAF bypass payloads.
  --test-CVE-2021-45046
                        Test using payloads for CVE-2021-45046 (detection payloads).
  --dns-callback-provider DNS_CALLBACK_PROVIDER
                        DNS Callback provider (Options: dnslog.cn, interact.sh) - [Default: interact.sh].
  --custom-dns-callback-host CUSTOM_DNS_CALLBACK_HOST
                        Custom DNS Callback Host.
  --disable-http-redirects
                        Disable HTTP redirects. Note: HTTP redirects are useful as it allows the payloads to have higher chance of reaching vulnerable systems.
  --threads
                        Amount of threads. Default is 20.
  --test
                        A canary host to test before the main list. Logs GET and POST requests examples..
```

## Scan a Single URL

```shell
$ python3 log4j-scan.py -u https://log4j.lab.secbot.local
```

## Scan a Single URL using all Request Methods: GET, POST (url-encoded form), POST (JSON body)


```shell
$ python3 log4j-scan.py -u https://log4j.lab.secbot.local --run-all-tests
```

## Discover WAF bypasses on the environment.

```shell
$ python3 log4j-scan.py -u https://log4j.lab.secbot.local --waf-bypass
```

## Scan a list of URLs

```shell
$ python3 log4j-scan.py -l urls.txt
```

# Installation

```
$ pip3 install -r requirements.txt
```

# Original
* FullHunt: [log4j-scan](https://github.com/fullhunt/log4j-scan)
