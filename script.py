import socket
import threading
import os
import json
import time
import urllib.request

import pydivert

# ===================== تنظیمات =====================
LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 8080

FAKE_SNI = b"snapp.ir"      # SNI جعلی (ثابت)
FAKE_MODE = "badsum"        # "badsum" یا "ttl"
FAKE_TTL = 5                # فقط برای حالت ttl (3 تا 10)
FAKE_REPEAT = 1             # تعداد بستهٔ جعلی (1 تا 3)

SPLIT_REAL = True           # شکستن ClientHello واقعی وسط SNI
SEND_FAKE_TO_SNAPP = False  # بستهٔ جعلی با مقصد IP اسنپ (آزمایشی)

BYPASS_ALL = False          # True = روی همهٔ سایت‌ها اعمال شود
DPI_DOMAINS = (
    'google.com', 'youtube.com', 'ytimg.com', 'ggpht.com',
    'googleusercontent.com', 'gstatic.com', 'googleapis.com',
    'youtu.be', 'googlevideo.com',
    # دامنه‌های فیلترشدهٔ دیگر را اینجا اضافه کن
)

CLEAN_IPS = {}              # مثال: {'google.com': '142.250.185.228'}
DEBUG = True
# ====================================================

DNS_CACHE = {}
ACTIVE_PORTS = set()
LOCK = threading.Lock()


def log(*a):
    if DEBUG:
        print(*a, flush=True)


def needs_bypass(host):
    if BYPASS_ALL:
        return True
    host = host.lower()
    return any(host == d or host.endswith('.' + d) for d in DPI_DOMAINS)


# ---------- DNS ----------
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


# ---------- ClientHello جعلی با SNI اسنپ ----------
def _ext(t, data):
    return t.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data


def build_fake_tls_hello(sni):
    n = len(sni)
    sni_ext = _ext(0, (n + 3).to_bytes(2, 'big') + b"\x00" + n.to_bytes(2, 'big') + sni)
    groups = _ext(10, b"\x00\x06\x00\x1d\x00\x17\x00\x18")
    sigalgs = _ext(13, b"\x00\x08\x04\x03\x08\x04\x04\x01\x05\x03")
    versions = _ext(43, b"\x04\x03\x04\x03\x03")
    exts = sni_ext + groups + sigalgs + versions

    ciphers = b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30"
    body = (
        b"\x03\x03" + os.urandom(32) +
        b"\x20" + os.urandom(32) +
        len(ciphers).to_bytes(2, 'big') + ciphers +
        b"\x01\x00" +
        len(exts).to_bytes(2, 'big') + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, 'big') + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, 'big') + hs


FAKE_HELLO = build_fake_tls_hello(FAKE_SNI)


# ---------- پیدا کردن SNI واقعی ----------
def find_sni_offset(data):
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


# ---------- تزریق با WinDivert ----------
def clone(pkt):
    return pydivert.Packet(bytearray(pkt.raw), pkt.interface, pkt.direction)


def inject_fake(w, pkt, dst_ip=None):
    fake = clone(pkt)
    fake.tcp.payload = FAKE_HELLO       # seq/ack/پورت‌ها همان بستهٔ واقعی
    if dst_ip:
        fake.dst_addr = dst_ip
    if FAKE_MODE == "ttl":
        fake.ipv4.ttl = FAKE_TTL
        w.send(fake)
    else:
        fake.recalculate_checksums()
        fake.tcp.cksum = (fake.tcp.cksum + 1) & 0xFFFF
        w.send(fake, recalculate_checksum=False)


def send_split(w, pkt, split_at):
    payload = bytes(pkt.tcp.payload)
    if split_at <= 0 or split_at >= len(payload):
        w.send(pkt)
        return
    p1 = clone(pkt)
    p1.tcp.payload = payload[:split_at]
    w.send(p1)

    p2 = clone(pkt)
    p2.tcp.seq_num = (pkt.tcp.seq_num + split_at) & 0xFFFFFFFF
    p2.tcp.payload = payload[split_at:]
    w.send(p2)


def divert_loop(snapp_ip):
    flt = "outbound and ip and tcp.DstPort == 443 and tcp.PayloadLength > 0"
    with pydivert.WinDivert(flt) as w:
        log(f"[*] WinDivert active | fake_sni={FAKE_SNI.decode()} "
            f"mode={FAKE_MODE} ttl={FAKE_TTL} split={SPLIT_REAL}")
        for pkt in w:
            handled = False
            try:
                with LOCK:
                    mine = pkt.src_port in ACTIVE_PORTS
                p = bytes(pkt.tcp.payload)
                if mine and len(p) > 6 and p[0] == 0x16 and p[5] == 0x01 \
                        and FAKE_SNI not in p:
                    for _ in range(FAKE_REPEAT):
                        inject_fake(w, pkt)
                    if SEND_FAKE_TO_SNAPP and snapp_ip:
                        inject_fake(w, pkt, dst_ip=snapp_ip)

                    if SPLIT_REAL:
                        sni = find_sni_offset(p)
                        cut = (sni[0] + max(1, sni[1] // 2)) if sni else 5
                        send_split(w, pkt, cut)
                        handled = True
                    log(f"[+] fake SNI={FAKE_SNI.decode()} injected"
                        f"{' + split' if SPLIT_REAL else ''}"
                        f" -> {pkt.dst_addr}:{pkt.dst_port}")
            except Exception as e:
                log(f"[!] inject error: {type(e).__name__}: {e}")
            if not handled:
                try:
                    w.send(pkt)
                except Exception as e:
                    log(f"[!] send error: {e}")


# ---------- پروکسی ----------
def pipe(src, dst):
    try:
        while True:
            data = src.recv(16384)
            if not data:
                break
            dst.sendall(data)
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
    """درخواست HTTP ساده (غیر CONNECT) را مستقیم فوروارد می‌کند"""
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
        r.settimeout(None)
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
    local_port = None
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
        remote.bind(('', 0))                       # پورت را قبل از connect بگیر
        local_port = remote.getsockname()[1]
        bypass = needs_bypass(host)
        if bypass:
            with LOCK:
                ACTIVE_PORTS.add(local_port)

        remote.settimeout(8)
        remote.connect((ip, int(port)))
        remote.settimeout(None)
        log(f"[+] connected {host} {ip} port={local_port} "
            f"{'[BYPASS]' if bypass else '[direct]'}")

        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        first_data = client.recv(16384)
        if first_data:
            remote.sendall(first_data)             # WinDivert اینجا دستکاری می‌کند

        t1 = threading.Thread(target=pipe, args=(client, remote), daemon=True)
        t2 = threading.Thread(target=pipe, args=(remote, client), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception as e:
        log(f"[!] handle_client error: {type(e).__name__}: {e}")
    finally:
        if local_port is not None:
            with LOCK:
                ACTIVE_PORTS.discard(local_port)
        for s in (client, remote):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def main():
    snapp_ip = resolve_ip("snapp.ir") if SEND_FAKE_TO_SNAPP else None
    threading.Thread(target=divert_loop, args=(snapp_ip,), daemon=True).start()
    time.sleep(0.5)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(200)
    log(f"[*] Proxy on {LISTEN_HOST}:{LISTEN_PORT} | fake SNI = {FAKE_SNI.decode()}")
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle_client, args=(c,), daemon=True).start()


if __name__ == '__main__':
    main()
