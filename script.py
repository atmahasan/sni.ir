import socket
import ssl

# مشخص کردن نام دامنه و آدرس IP سرور
دامنه = "snap.ir"
آدرس_آی‌پی = socket.gethostbyname(دامنه)

# ایجاد یک اتصال اس‌اس‌ال به سرور
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection((آدرس_آی‌پی, 443)) as sock:
 with context.wrap_socket(sock, server_hostname=دامنه) as ssock:
 # ارسال یک درخواست GET به صفحه اصلی
 request = f"GET / HTTP/1.1\r\nHost: {دامنه}\r\n\r\n"
 ssock.sendall(request.encode())
 response = ssock.recv(1024)
 print(response.decode())
