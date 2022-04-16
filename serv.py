from curses.ascii import US
import socket 
import threading
import sys 
import ssl
import hashlib
from time import sleep
import ast
import os
from dotenv import load_dotenv
load_dotenv()
#gittest
USERS = ast.literal_eval(os.getenv('USRS'))
HEADER = 64
PORT = int(sys.argv[2])
SERVER = sys.argv[1]
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!OVER"
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('certificate.pem', 'key.pem')
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clients = {}
def writeUsrs(dict):
   with open('.env', 'w') as f:
       f.write('USRS="'+str(dict)+'"')
       f.truncate()
       f.close()

def handle_client(conn, addr):
    try:
        conn.settimeout(60)
        print(f"[CONNECTION] {addr} {conn} connected.")
        hed = conn.recv(HEADER).decode(FORMAT)
        print(f'[HEADER] {hed}')
        connected = False
        if hed == '0':
            print(f"[CONNECTION] Login attempt from {addr}")
            user = conn.recv(HEADER).decode(FORMAT)
            print(f"[CONNECTION] {user} Logging in...")
            passw = conn.recv(HEADER).decode(FORMAT)
            try:
                print(USERS[user], passw, hashlib.sha256(passw.encode('utf-8')).hexdigest())
                if USERS[user] == hashlib.sha256(passw.encode('utf-8')).hexdigest():
                    if user not in clients:
                        connected = True
                        clients[user] = [conn, ""]
                        print(f"[CONNECTION] {user} Logged In")
                    elif user in clients:
                        print(f"[CONNECTION] {user} Already Logged In")
                        conn.send("ALRCON".encode(FORMAT))
                        conn.close()
                        return
                else:
                    conn.send("FAILED".encode(FORMAT))
            except KeyError:
                conn.send("NOACC".encode(FORMAT))
            conn.send("ACCGNT".encode(FORMAT))
            print('test1')
            print(connected)
            a = 0
            while connected:
                sleep(5)
                msg = conn.recv(HEADER).decode(FORMAT)
                print(msg)
                if msg == "!OVER" or msg == "kepalv" or msg.startswith("cmd") or msg.startswith("pasch"):

                    if msg == DISCONNECT_MESSAGE:
                        connected = False
                        raise Exception("DISMSG")
                    if msg == "kepalv":
                        print('ok')
                        if not clients[user][1]:
                            conn.send("1".encode(FORMAT))
                        elif clients[user][1]:
                            tosend = "msg:"+clients[user][1]
                            conn.send(tosend.encode(FORMAT))
                            clients[user][1] = ""
                    if msg.startswith("cmd"):
                        if msg[3:].startswith("sendall "):
                            for i in clients:
                                if i != user:
                                    clients[i][1] = msg[11:]
                            conn.send("Sent".encode(FORMAT))
                        if msg[3:] == "exit":
                            break
                    if msg.startswith("pasch"):
                        USERS[user] = hashlib.sha256(msg[5:].encode('utf-8')).hexdigest()
                        writeUsrs(USERS)
                        conn.send("good".encode(FORMAT))

                else:
                    raise Exception("BADMSG")                
        conn.close()
        raise Exception("LOPESC") 
    except Exception as e:
        print(f"[CONNECTION] {addr} disconnected. ({e})")
        del clients[user]


def start():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(ADDR)
        sock.listen()
        print(f"[LISTENING] Server is listening on {SERVER}")
        with context.wrap_socket(sock, server_side=True) as ssock:
            sockets_list = [ssock]
            print("[LISTENING] Encryption enabled")
            while True:
                conn, addr = ssock.accept()
                print(clients)
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.start()
                print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")
print("[STARTING] server is starting...")
start()
 #TODO: Add a change password function, write new users to file.
 #TODO: Add a command line interface for admin.
 #TODO: Add a GUI for client.
 #TODO: Add update on server side.