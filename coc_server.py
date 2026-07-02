import socket, struct

PSM = 0x0081
ADDR_TYPE = socket.BDADDR_LE_PUBLIC

s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)

# 1) bind D'ABORD : type la source en LE ; (PSM + src LE) => passage auto en LE_FLOWCTL
s.bind((socket.BDADDR_ANY, PSM, 0, ADDR_TYPE))

# 2) BT_MODE maintenant accepté (état BT_BOUND + src LE) — sert d'assertion
s.setsockopt(socket.SOL_BLUETOOTH, socket.BT_MODE, struct.pack("B", socket.BT_MODE_LE_FLOWCTL))
print("[server] BT_MODE = LE_FLOWCTL OK", flush=True)

# 3) sécurité, puis listen
s.setsockopt(socket.SOL_BLUETOOTH, socket.BT_SECURITY, struct.pack("BB", socket.BT_SECURITY_MEDIUM, 0))
s.listen(1)
print("[server] listening...", flush=True)

conn, addr = s.accept()   # le socket accepté hérite du mode du parent
print(f"[server] connected by {addr}", flush=True)
while True:
    data = conn.recv(1024)
    if not data:
        print("[server] peer closed", flush=True)
        break
    print(f"[server] GOT {len(data)} bytes: {data!r}", flush=True)
    conn.send(b"ACK " + data)   # echo : prouve le sens serveur->client dans le même run
conn.close()
s.close()
