import socket
import ssl

# مشخص کردن نام دامنه و آدرس IP سرور
domain = "snap.ir"
ip_address = "127.0.0.1"

# ایجاد یک اتصال SSL
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# ایجاد یک سوکت
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# اتصال به سرور
sock.connect((ip_address, 443))

# ایجاد یک اتصال SSL
ssl_sock = context.wrap_socket(sock, server_hostname=domain)

# ارسال درخواست SNI
ssl_sock.sendall(b"GET / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\n\r\n")

# دریافت پاسخ
response = ssl_sock.recv(1024)

# چاپ پاسخ
print(response.decode())

# بستن اتصال
ssl_sock.close()
sock.close()
