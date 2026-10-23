import socket
import threading
import time
import json
import urllib.request

LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 8080

SPLIT_DELAY = 0.05     # اگر کار نکرد 0.1 تا 0.3 را امتحان کن
FRAG_COUNT = 2         # تعداد تکه (2 یا 3)

CLEAN_IPS = {}         # مثلا {'google.com': '142.250.185.228'} اگر لازم شد
DEBUG = True

DNS_CACHE = {}


def log(*a):
    if DEBUG:
        print(*a, flush=True)


def resolve_ip(host):
    for key, ip in CLEAN_IPS.items():
        if host == key or host.endswith('.' + key):
            return ip
    if host in DNS_CACHE:
        return DNS_CACHE[host]
    try:
        url = f"https://1.1.1.1/dns-query?name={host}&type=A"
        req = urllib.request.Request(url, headers={'Accept': 'application/dns-json'})
        with urllib.request.urlopen(req, timeout=5) as res:
            for ans in json.loads(res.read().decode()).get('Answer', []):
                if ans.get('type') == 1:
                    DNS_CACHE[host] = ans['data']
                    return ans['data']
    except Exception as e:
        log(f"[!] DoH failed for {host}: {e}")
    try:
        ip = socket.gethostbyname(host)
        DNS_CACHE[host] = ip
        return ip
    except Exception as e:
        log(f"[!] DNS failed for {host}: {e}")
        return None


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def read_client_hello(sock):
    """کل رکورد اول TLS (ClientHello) را می‌خواند، حتی اگر چند بسته TCP باشد"""
    hdr = recv_exact(sock, 5)
    if len(hdr) < 5:
        return hdr
    if hdr[0] != 0x16:
        # غیر TLS: هرچه در دسترس است را برگردان
        return hdr + sock.recv(16384)
    rec_len = int.from_bytes(hdr[3:5], 'big')
    body = recv_exact(sock, rec_len)
    return hdr + body


def find_sni(data):
    """offset و طول نام دامنه در ClientHello، یا None"""
    try:
        pos = 5 + 4 + 2 + 32
        pos += 1 + data[pos]
        pos += 2 + int.from_bytes(data[pos:pos + 2], 'big')
        pos += 1 + data[pos]
        ext_end = pos + 2 + int.from_bytes(data[pos:pos + 2], 'big')
        pos += 2
        while pos + 4 <= ext_end:
            etype = int.from_bytes(data[pos:pos + 2], 'big')
            elen = int.from_bytes(data[pos + 2:pos + 4], 'big')
            if etype == 0:
                name_len = int.from_bytes(data[pos + 7:pos + 9], 'big')
                return pos + 9, name_len
            pos += 4 + elen
    except Exception:
        pass
    return None


def fragment_hello(data, n_parts):
    """ClientHello را به n_parts رکورد TLS کوچک می‌شکند، برش از وسط SNI"""
    rec_len = int.from_bytes(data[3:5], 'big')
    payload = data[5:5 + rec_len]
    rest = data[5 + rec_len:]

    sni = find_sni(data)
    if sni:
        off, name_len = sni
        center = (off - 5) + name_len // 2
        step = max(1, name_len // max(1, n_parts))
        raw_cuts = [center + (i - n_parts // 2) * step for i in range(n_parts)]
    else:
        raw_cuts = [len(payload) // 2]

    cuts = sorted(set(c for c in raw_cuts if 0 < c < len(payload)))

    records = []
    prev = 0
    for c in cuts:
        chunk = payload[prev:c]
        if chunk:
            records.append(data[:3] + len(chunk).to_bytes(2, 'big') + chunk)
        prev = c
    last = payload[prev:]
    if last:
        records.append(data[:3] + len(last).to_bytes(2, 'big') + last + rest)
    else:
        records[-1] = records[-1] + rest
    return records


def pipe(src, dst):
    try:
        while True:
            d = src.recv(16384)
            if not d:
                break
            dst.sendall(d)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.close()
            except Exception:
                pass


def recv_headers(sock):
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 16384:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_plain_http(client, req):
    r = None
    try:
        hdr = req.decode('latin1')
        hostline = [l for l in hdr.split('\r\n') if l.lower().startswith('host:')]
        if not hostline:
            return
        h = hostline[0].split(':', 1)[1].strip()
        hh, _, pp = h.partition(':')
        ip = resolve_ip(hh)
        if not ip:
            return
        r = socket.create_connection((ip, int(pp or 80)), timeout=8)
        r.sendall(req)
        threading.Thread(target=pipe, args=(client, r), daemon=True).start()
        pipe(r, client)
    except Exception as e:
        log(f"[!] plain http error: {e}")
    finally:
        for s in (client, r):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def handle_client(client):
    remote = None
    try:
        req = recv_headers(client)
        if not req:
            client.close()
            return
        first = req.split(b"\r\n")[0].decode('latin1')

        if not first.startswith('CONNECT'):
            handle_plain_http(client, req)
            return

        host, port = first.split(' ')[1].rsplit(':', 1)
        ip = resolve_ip(host)
        if not ip:
            client.close()
            return

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        remote.settimeout(8)
        remote.connect((ip, int(port)))
        remote.settimeout(None)
        log(f"[+] connected {host} {ip}")

        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        first_data = read_client_hello(client)
        if not first_data:
            client.close()
            remote.close()
            return

        if first_data[0] == 0x16 and len(first_data) > 5 and first_data[5] == 0x01:
            parts = fragment_hello(first_data, FRAG_COUNT)
            for i, part in enumerate(parts):
                remote.sendall(part)
                if i < len(parts) - 1:
                    time.sleep(SPLIT_DELAY)
            log(f"[+] fragmented ClientHello ({len(parts)} parts) -> {host}")
        else:
            remote.sendall(first_data)

        t1 = threading.Thread(target=pipe, args=(client, remote), daemon=True)
        t2 = threading.Thread(target=pipe, args=(remote, client), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
    except Exception as e:
        log(f"[!] handle_client error: {type(e).__name__}: {e}")
    finally:
        for s in (client, remote):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(200)
    log(f"[*] SNI-fragment proxy on {LISTEN_HOST}:{LISTEN_PORT}")
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle_client, args=(c,), daemon=True).start()


if __name__ == '__main__':
    main()
