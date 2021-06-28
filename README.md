# WebForce


[![python](https://img.shields.io/badge/python-3-blue.svg)](https://www.python.org/downloads/)
[![GitHub version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=gh&type=6&v=1.0&x2=0)](https://github.com/pwnsociety)
<a href="https://twitter.com/pwnsociety" target="_blank">
  <img src="http://jpillora.com/github-twitter-button/img/tweet.png" alt="tweet button" ></img>
</a>


Table of Contents
------------
* [Installation](#Installation--Usage)
* [How To use](#How-to-use)
  * [Scan Sql injection](#Scan-Sql-injection)
  * [Scan Xss](#Scan-Xss)
  * [Scan LFI injection](#Scan-LFI-injection)
  * [Scan CORS Vulnerability](#Scan-CORS-Vulnerability)
  * [Scan SSI injection](#Scan-SSI-injection)
  * [Scan CRLF injection](#Scan-CRLF-injection)
  * [Scan SSTI injection](#Scan-SSTI-injection)
  * [Fast recon for XXE](#Fast-recon-for-XXE)
  * [Scan sub-directories](#Scan-sub-directories)
  * [Scan HTTP Parameter Pollution vulnerabilities](#Proxies)

* [License](#License)


Installation & Usage
------------

**Requirement: python 3.7 or higher**

Choose one of these installation options:

- Install with git: `git clone https://github.com/pwnsociety/WebForce.git`
- Install with ZIP file: [Download here](https://github.com/pwnsociety/WebForce/archive/refs/heads/main.zip)

How to use
---------------

**All in one:**
```
git clone https://github.com/pwnsociety/WebForce.git
cd WebForce
python3 WebForce.py -u "https://website.com/somewhere?id=" --all
```

**Help Command:**
```
.--.     v1.0.0   
            ,-.------+-.|  ,-.     
   ,--=======* )"("")===)===* )    
   �        -"---==-+-"|  -"     
   O                 '--'     github.com/Pwnsociety 


[+] Started scanning @ 12:15:39

usage: WebForce.py [-h] [-u FULL_SITE] [-a] [--xss] [--ssti] [--ignore-ssl] [--lfi] [--sqli] [--cors] [--ssi]
                   [--crlf] [--xxe] [--open-redirect] [--parameter-pollution] [--user-agent] [--cookie-scan]
                   [--cipher CIPHER_SCAN] [--proxy PROXY_ARG] [--redirect] [--cookies COOKIES] [--no-param]
                   [--list] [--verbose] [--version]

Example : python3 WebForce.py -u "https://website.com/somewhere?id=" --all

optional arguments:
  -h, --help            show this help message and exit
  -u FULL_SITE, --url FULL_SITE
                        Target URL (e.g. "http://www.site.com/vuln.php?id=1")
  -a, --all             Scan for every possible vulnerability
  --xss                 Scan only for XSS
  --ssti                Scan only for SSTI injection
  --ignore-ssl          Ignore SSL errors while scanning
  --lfi                 Scan only for LFI injection
  --sqli                Scan only for SQL injection
  --cors                Scan only for CORS vulnerability
  --ssi                 Scan only for SSI injection
  --crlf                Scan only for CRLF injection
  --xxe                 Fast recon for XXE
  --open-redirect       Scan only for Open Redirect vulnerability
  --parameter-pollution
                        Scan only for HTTP Parameter pollution vulnerabilities
  --user-agent          Scan only for every possible User-Agent HTTP Header vulnerability
  --cookie-scan         Detect possible vulnerabilities by deciphering the cookie value
  --cipher CIPHER_SCAN  Detect possible vulnerabilities by deciphering the cookie value
  --proxy PROXY_ARG     Scan using proxy (e.g "127.0.0.1:8080")
  --redirect            Allow redirecting when sending request
  --cookies COOKIES     Specify cookies (in JSON format)
  --no-param            Dont specify GET parameters on URL
  --list                List all vulnerabilities that this scanner is able to do
  --verbose             Enable real-time scan information
  --version             show program's version number and exit
  ```
