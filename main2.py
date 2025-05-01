import threading
import socket
from datetime import datetime
import json
import os
import time
import signal
import sys
from scapy.all import *
from http.server import BaseHTTPRequestHandler, HTTPServer
from flask import Flask, request, render_template_string
from collections import defaultdict, deque

# --- Base directory and logging ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
log_lock = threading.Lock()

# --- Bot/Scanner Detection State ---
connection_history = defaultdict(lambda: deque(maxlen=10))  # IP -> timestamps

def is_bot(ip):
    now = time.time()
    dq = connection_history[ip]
    dq.append(now)
    # If more than 3 connections in 5 seconds, consider as bot/scanner
    return len(dq) >= 3 and (dq[-1] - dq[0]) < 5

def logger(protocol, ip, port, data):
    # Only log ONVIF, RTSP, ICMP if bot detected
    if protocol in ("ONVIF", "RTSP", "ICMP") and not is_bot(ip):
        return
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "protocol": protocol,
        "ip": ip,
        "port": port,
        "data": data.decode(errors='ignore')[:200] if isinstance(data, bytes) else str(data)[:200]
    }
    log_filename = os.path.join(LOG_DIR, f"{protocol.lower()}.log")
    with log_lock:
        with open(log_filename, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    print(f"[{protocol}] {ip}:{port} logged to {log_filename}.")

# --- Flask Fake NVR Login (Port 5050) ---
app = Flask(__name__)

CORRECT_USERNAME = "admin"
CORRECT_PASSWORD = "123456"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Legitimate NVR</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(#1c1c1c, #2c2c2c);
            color: #fff;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-box {
            background: #1b1b1b;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.5);
            width: 350px;
        }
        .login-box h2 {
            margin-bottom: 20px;
            text-align: center;
            color: #e60012;
        }
        .error-message {
            color: red;
            text-align: center;
            margin-bottom: 15px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            background: #333;
            border: 1px solid #444;
            color: #fff;
            border-radius: 5px;
        }
        button {
            width:100%;
            padding: 10px;
            background-color: #e60012;
            border: none;
            color: #fff;
            font-weight: bold;
            border-radius: 5px;
            cursor: pointer;
        }
        button:hover {
            background-color: #ff1a25;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Legitimate NVR</h2>
        {% if error %}
            <div class="error-message">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    client_ip = request.remote_addr
    connection_history[client_ip].append(time.time())
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        logger("HTTP-LOGIN", client_ip, 5050, f"Username: {username}, Password: {password}")
        if username == CORRECT_USERNAME and password == CORRECT_PASSWORD:
            return "<h2 style='color:#fff; background:#111; padding:20px;'>Login successful!</h2>"
        else:
            error = "Invalid username or password"
    return render_template_string(HTML_TEMPLATE, error=error)

@app.route('/admin')
def admin():
    return "<h2 style='color:#fff; background:#111; padding:20px;'>Admin Page</h2>"

def run_flask():
    app.run(host="0.0.0.0", port=5050)

# --- RTSP Server (Port 554) ---
def rtspServer():
    try:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        soc.bind(('0.0.0.0', 554))
        soc.listen(5)
        print("RTSP server listening on port 554...")
        while True:
            conn, addr = soc.accept()
            ip, port = addr
            connection_history[ip].append(time.time())
            conn.settimeout(2)
            try:
                data = conn.recv(1024)
                if data:
                    logger("RTSP", ip, port, data)
                else:
                    logger("RTSP", ip, port, b"No data received")
            except socket.timeout:
                logger("RTSP", ip, port, b"No data received (timeout)")
            except Exception as e:
                print(f"[RTSP ERROR] {e}")
            finally:
                conn.close()
    except Exception as e:
        print(f"[RTSP ERROR] {e}")

# --- ONVIF Server (Port 80) ---
def onvifServer():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', 80))
        s.listen(5)
        print("ONVIF server listening on port 80...")
        while True:
            conn, addr = s.accept()
            ip, port = addr
            connection_history[ip].append(time.time())
            conn.settimeout(2)
            try:
                data = conn.recv(1024)
                if data:
                    if b"<SOAP" in data or b"Probe" in data:
                        logger("ONVIF", ip, port, data)
                    # Fake ONVIF response
                    fake_response = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: onvif_application/soap+xml; charset=utf-8\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n"
                    )
                    conn.sendall(fake_response.encode())
                else:
                    logger("ONVIF", ip, port, b"No data received")
            except socket.timeout:
                logger("ONVIF", ip, port, b"No data received (timeout)")
            except Exception as e:
                print(f"[ONVIF ERROR] {e}")
            finally:
                conn.close()
    except Exception as e:
        print(f"[ONVIF ERROR] {e}")

# --- HTTP Honeypot (Port 8888) ---
class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        ip = self.client_address[0]
        connection_history[ip].append(time.time())
        logger("HTTP", ip, self.client_address[1], b"GET request")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Sike! That's the wrong number!")

    def do_POST(self):
        ip = self.client_address[0]
        connection_history[ip].append(time.time())
        content_length = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_length)
        logger("HTTP", ip, self.client_address[1], post_body)
        self.send_response(403)
        self.end_headers()

    def log_message(self, format, *args):
        return  # Suppress default logging

def http():
    try:
        httpd = HTTPServer(('0.0.0.0', 8888), handler)
        print("HTTP server listening on port 8888...")
        httpd.serve_forever()
    except Exception as e:
        print(f"[HTTP ERROR] {e}")

# --- ICMP Sniffer ---
def icmpSniffer():
    try:
        print("ICMP sniffer started... (listening for ping requests)")

        def process_packet(packet):
            if packet.haslayer(ICMP) and packet[ICMP].type == 8:
                ip = packet[IP].src
                logger("ICMP", ip, 0, f"ICMP Echo Request from {ip}")

        sniff(prn=process_packet, filter="icmp", store=0)
    except Exception as e:
        print(f"[ICMP ERROR] {e}")

# --- Graceful Shutdown ---
def signal_handler(sig, frame):
    print("Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# --- Main ---
if __name__ == "__main__":
    threading.Thread(target=run_flask, daemon=True).start()
    threading.Thread(target=rtspServer, daemon=True).start()
    threading.Thread(target=onvifServer, daemon=True).start()
    threading.Thread(target=http, daemon=True).start()
    threading.Thread(target=icmpSniffer, daemon=True).start()
    print("Honeypot running. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)
