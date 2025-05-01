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

# Base directory setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Thread-safety for logging
log_lock = threading.Lock()

def logger(protocol, ip, port, data):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "protocol": protocol,
        "ip": ip,
        "port": port,
        "data": data.decode(errors='ignore')[:200] if isinstance(data, bytes) else str(data)[:200]
    }

    log_filename = os.path.join(LOG_DIR, "honeypot.log")
    if protocol == "ONVIF":
        log_filename = os.path.join(LOG_DIR, "onvif.log")
    elif protocol == "HTTP":
        log_filename = os.path.join(LOG_DIR, "http.log")
    elif protocol == "ICMP":
        log_filename = os.path.join(LOG_DIR, "icmp.log")
    elif protocol == "RTSP":
        log_filename = os.path.join(LOG_DIR, "rtsp.log")

    with log_lock:
        with open(log_filename, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    print(f"[{protocol}] {ip}:{port} logged to {log_filename}.")

def rtspServer():
    try:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.bind(('0.0.0.0', 554))
        soc.listen(5)
        print("RTSP server listening on port 554...")
        while True:
            conn, addr = soc.accept()
            conn.settimeout(2)
            try:
                data = conn.recv(1024)
                if data:
                    print(f"[RTSP] Connection from {addr[0]}:{addr[1]} - DATA: {data[:100]}")
                    logger("RTSP", addr[0], addr[1], data)
                else:
                    logger("RTSP", addr[0], addr[1], b"No data received")
            except socket.timeout:
                logger("RTSP", addr[0], addr[1], b"No data received (timeout)")
            except Exception as e:
                print(f"[RTSP ERROR] {e}")
            finally:
                conn.close()
    except Exception as e:
        print(f"[RTSP ERROR] {e}")

def onvifServer():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', 80))
        s.listen(5)
        print("ONVIF server listening on port 80...")
        while True:
            conn, addr = s.accept()
            conn.settimeout(2)
            try:
                data = conn.recv(1024)
                if data:
                    if b"<SOAP" in data or b"Probe" in data:
                        logger("ONVIF", addr[0], addr[1], data)

                    # ➔ Fake ONVIF response
                    fake_response = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: onvif_application/soap+xml; charset=utf-8\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n"
                    )
                    conn.sendall(fake_response.encode())
                else:
                    logger("ONVIF", addr[0], addr[1], b"No data received")
            except socket.timeout:
                logger("ONVIF", addr[0], addr[1], b"No data received (timeout)")
            except Exception as e:
                print(f"[ONVIF ERROR] {e}")
            finally:
                conn.close()
    except Exception as e:
        print(f"[ONVIF ERROR] {e}")

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        logger("HTTP", self.client_address[0], self.client_address[1], b"GET request")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Sike! That's the wrong number!")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_length)
        logger("HTTP", self.client_address[0], self.client_address[1], post_body)
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

def cowrie():
    try:
        with open(os.path.join(LOG_DIR, "cowrie.json"), "r") as f:
            for line in f:
                print("[SSH-HONEYPOT]", line.strip())
    except FileNotFoundError:
        print("[COWRIE] cowrie.json not found.")

# Graceful shutdown handler
def signal_handler(sig, frame):
    print("Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    threading.Thread(target=rtspServer, daemon=True).start()
    threading.Thread(target=onvifServer, daemon=True).start()
    threading.Thread(target=http, daemon=True).start()
    threading.Thread(target=icmpSniffer, daemon=True).start()

    while True:
        time.sleep(1)