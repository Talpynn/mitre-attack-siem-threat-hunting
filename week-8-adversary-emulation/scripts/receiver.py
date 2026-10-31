"""Lab-only HTTP receiver. Accepts only the fixed Week 8 dummy payload."""
import argparse
import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PAYLOAD = b'WEEK8-LAB-DUMMY-DATA\nNo real credentials or personal data.\n'


def allowed_ip(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or not (address.is_loopback or any(address in ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))):
        raise argparse.ArgumentTypeError('Use an explicit RFC1918 or loopback IPv4 address')
    return str(address)


class Receiver(BaseHTTPRequestHandler):
    def __init__(self, *args, output, **kwargs):
        self.output = Path(output)
        super().__init__(*args, **kwargs)

    def do_POST(self):
        self.connection.settimeout(5)
        if self.path != '/upload':
            self.send_error(404)
            return
        if self.headers.get('Transfer-Encoding'):
            self.send_error(400, 'Chunked requests are not supported')
            return
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            length = -1
        if length != len(PAYLOAD):
            self.send_error(400, 'Only the fixed dummy payload is accepted')
            return
        try:
            content = self.rfile.read(length)
        except (TimeoutError, OSError):
            self.send_error(408)
            return
        if content != PAYLOAD:
            self.send_error(400, 'Dummy payload mismatch')
            return
        now = datetime.now(timezone.utc)
        name = now.strftime('%Y%m%dT%H%M%S%fZ') + '-dummy-data.txt'
        self.output.mkdir(parents=True, exist_ok=True)
        (self.output / name).write_bytes(content)
        record = dict(timestamp=now.isoformat(), source_ip=self.client_address[0],
                      path=self.path, bytes=len(content), sha256=hashlib.sha256(content).hexdigest(),
                      saved_file=name, status=201)
        with (self.output / 'receiver.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(record) + '\n')
        body = json.dumps(record).encode('utf-8')
        self.send_response(201)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', required=True, type=allowed_ip)
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--output', type=Path, default=Path('received'))
    args = parser.parse_args()
    server = HTTPServer((args.bind, args.port), partial(Receiver, output=args.output))
    print(f'Lab receiver at http://{args.bind}:{args.port}/upload; stop with Ctrl+C', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
