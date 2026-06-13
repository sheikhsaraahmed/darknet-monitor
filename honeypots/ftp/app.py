import socket
import threading
import datetime
import json
import os

LOG_FILE = "/logs/ftp_honeypot.log"

def log_attempt(ip, data):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "ip": ip,
        "data": data
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print("[FTP ATTACK] " + str(entry))

def handle_client(conn, addr):
    ip = addr[0]
    print("[FTP] Connection from " + ip)
    conn.send(b"220 FTP Server Ready\r\n")
    username = ""
    try:
        while True:
            data = conn.recv(1024).decode(errors="ignore").strip()
            if not data:
                break
            print("[FTP] " + ip + " sent: " + data)
            if data.upper().startswith("USER"):
                username = data[5:]
                log_attempt(ip, {"command": "USER", "username": username})
                conn.send(b"331 Password required\r\n")
            elif data.upper().startswith("PASS"):
                password = data[5:]
                log_attempt(ip, {"command": "PASS", "username": username, "password": password})
                conn.send(b"530 Login incorrect\r\n")
            elif data.upper().startswith("QUIT"):
                conn.send(b"221 Goodbye\r\n")
                break
            else:
                log_attempt(ip, {"command": data})
                conn.send(b"500 Unknown command\r\n")
    except Exception as e:
        print("[FTP] Error: " + str(e))
    finally:
        conn.close()

def start_server():
    os.makedirs("/logs", exist_ok=True)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 21))
    server.listen(5)
    print("[FTP] Honeypot listening on port 21")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    start_server()