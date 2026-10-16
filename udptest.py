import socket, struct, os, sys
H = os.environ.get('FP_HOST', 'resi.fastproxy.to'); P = int(os.environ.get('FP_PORT', '9696'))
user = input('Username (pakai session tetap, mis. ...-session-udp0001-time-long): ').strip()
pw = input('Password: ').strip()
q = bytes.fromhex('123401000001000000000000076578616d706c6503636f6d0000010001')
s = socket.create_connection((H, P), timeout=15)
s.sendall(b'\x05\x01\x02')
r = s.recv(2)
if len(r) < 2 or r[1] != 2: print('Server tidak minta user/pass, balasan:', r); sys.exit(1)
u, p = user.encode(), pw.encode()
s.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
a = s.recv(2)
if len(a) < 2 or a[1] != 0: print('LOGIN DITOLAK:', a); sys.exit(1)
print('1) Login SOCKS5: OK')
s.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
rep = s.recv(262)
if len(rep) < 10 or rep[1] != 0:
    print('2) UDP ASSOCIATE DITOLAK, kode balasan =', rep[1] if len(rep) > 1 else rep, '(7 = command not supported)'); sys.exit(1)
atyp = rep[3]
if atyp == 1: baddr = socket.inet_ntoa(rep[4:8]); bport = struct.unpack('>H', rep[8:10])[0]
else: print('2) UDP ASSOCIATE diterima, tipe alamat', atyp, 'tidak dikenal oleh tes ini:', rep.hex()); sys.exit(1)
relay = baddr if baddr != '0.0.0.0' else socket.gethostbyname(H)
print('2) UDP ASSOCIATE: OK  relay =', relay, 'port', bport, '(IP proxy yang dipakai tunnel: %s)' % socket.gethostbyname(H))
u_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u_s.settimeout(8)
u_s.sendto(b'\x00\x00\x00\x01' + socket.inet_aton('1.1.1.1') + struct.pack('>H', 53) + q, (relay, bport))
try:
    d, src = u_s.recvfrom(2048)
    print('3) Balasan DNS lewat UDP relay: OK (%d byte dari %s)' % (len(d), src[0]))
except socket.timeout:
    print('3) Tidak ada balasan UDP dalam 8 detik (relay menerima tapi tidak meneruskan, atau UDP diblok)')
