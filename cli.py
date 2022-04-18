import socket
import sys
import getpass
import ssl
import threading
from urllib import response
import requests
from time import sleep

HEADER = 64
PORT = int(sys.argv[2])
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!OVER"
SERVER = sys.argv[1]
ADDR = (SERVER, PORT)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations('certificate.pem')
context.check_hostname = False
while True:
    try:
        with socket.create_connection((SERVER, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=SERVER) as ssock:
                ssock.settimeout(60)
                print(ssock.version())
                print(ssock.cipher()[0])
                print("THIS SOFTWARE IS IN ALPHA")
                def keal():
                    global aaa
                    global repl
                    aaa = "kepalv"
                    repl = ""
                    while True:
                        try:
                            while True:
                                sleep(10)
                                if aaa != "kepalv":
                                    repl = "\n" + send(aaa)
                                    print(repl)
                                    aaa = "kepalv"
                                    raise Exception("reset7")
                                else:
                                    chk = send("kepalv")
                                    if chk != "1":
                                        print("\n" + chk)
                                        if chk.startswith("update"):
                                            print("Updating...")
                                            response = requests.get(chk)
                                            open("test", "wb").write(response.content)
                        except:
                            pass
                def head(type): 
                    if type == 0:
                        ssock.send(str(0).encode())
                        #Get user creds + error codes
                        getuser = input("User:")
                        getred = getpass.getpass(prompt='Password: ', stream=None)
                        tryauth = auth(getred, getuser)
                        if tryauth == "ACCGNT":
                            print("Login Successful")
                            return "ACCGNT"
                        elif tryauth == "NOACC":
                            print("Username not found")
                            sys.exit(1)
                        elif tryauth == "FAILED":
                            print("Wrong Password")
                            sys.exit(1)
                        elif tryauth == "ALRCON":
                            print("Already Logged In")
                            sys.exit(1)
                        else:
                            print("Something went wrong")
                            sys.exit(1)
                def auth(passw, uawe):  
                    #authentication function
                    ssock.send(uawe.encode(FORMAT))
                    ssock.send(passw.encode(FORMAT))
                    return ssock.recv(2048).decode(FORMAT)
                def send(msg):  
                    message = msg.encode(FORMAT)
                    ssock.send(message)
                    if msg == "!OVER":
                        print("DISCONNECTED")
                        sys.exit(0)
                    return ssock.recv(2048).decode(FORMAT)
                if head(0) == "ACCGNT":
                    thread = threading.Thread(target=keal)
                    thread.start()
                    while True:
                        aa = input(">")
                        if aa == "chpass":
                            print("Changing Password")
                            newpass = getpass.getpass(prompt='New Password: ', stream=None)
                            newpass2 = getpass.getpass(prompt='Confirm Password: ', stream=None)
                            if newpass == newpass2:
                                print("Password change:" + send('pasch'+newpass))
                            else:
                                print("Passwords do not match")
                        elif aa == "cmd":
                            aaa = 'cmd' + input("cmd>")
                        else:
                            aaa = 'cmdsendall'+aa
    except socket.timeout:
        print("Timeout")