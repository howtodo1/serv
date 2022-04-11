import socket 
import threading
import sys 
import ssl
import hashlib
from time import sleep
USERS = {"user1":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "user2":"07123e1f482356c415f684407a3b8723e10b2cbbc0b8fcd6282c49d37c9c1abc"}
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
test = "test"
def handle_client(conn, addr):
    try:
        conn.settimeout(60)
        print(f"[CONNECTION] {addr} {conn} connected.")
        hed = conn.recv(HEADER).decode(FORMAT)
        print(f'[HEADER] {hed}')
        connected = False
        if hed == '0':
            print(f"[CONNECTION] ??? Logging in...")
            user = conn.recv(HEADER).decode(FORMAT)
            print(f"[CONNECTION] {user} Logging in...")
            passw = conn.recv(HEADER).decode(FORMAT)
            try:
                print(USERS[user], passw, hashlib.sha256(passw.encode('utf-8')).hexdigest())
                if USERS[user] == hashlib.sha256(passw.encode('utf-8')).hexdigest():
                    print(f"[CONNECTION] {user} Logged In")
                    connected = True
                    clients[user] = [conn, ""]
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
                if msg == "!OVER" or msg == "kepalv" or msg.startswith("cmd"):
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
                        if msg[3:] == "test":
                            conn.send(test.encode(FORMAT))
                            test == test+test
                        if msg[3:] == "exit":
                            break
                else:
                    raise Exception("BADMSG")
        conn.close()
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
