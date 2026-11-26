"""HTTPS for the simulated internet (many site names, one server) and for the C2 server.
--c2 also listens on 8443 for a long-lived raw TLS channel (an interactive tunnel)."""
import http.server
import json
import os
import socketserver
import ssl
import sys
import threading

C2 = "--c2" in sys.argv


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if C2:
            body = json.dumps({"task": "sleep", "jitter": 0.2}).encode()
        else:
            body = os.urandom(int.from_bytes(os.urandom(2), "big") % 40_000 + 2_000).hex().encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def tls(sock):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/tmp/c.pem", "/tmp/k.pem")
    return ctx.wrap_socket(sock, server_side=True)


def tunnel():
    class T(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                c = tls(self.request)
                while data := c.recv(4096):
                    c.sendall(data[::-1])
            except Exception:
                pass

    class TS(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    TS(("0.0.0.0", 8443), T).serve_forever()


if C2:
    threading.Thread(target=tunnel, daemon=True).start()
srv = S(("0.0.0.0", 443), H)
srv.socket = tls(srv.socket)
srv.serve_forever()
