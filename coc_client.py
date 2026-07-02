import socket, struct, time

SERVER_ADDR = "9C:B8:B4:9F:2D:75"
PSM = 0x0081
ADDR_TYPE = socket.BDADDR_LE_PUBLIC

s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)

# 1) LA LIGNE QUI CHANGE TOUT : bind local LE avant connect.
#    psm=0 => auto-allocation d'un PSM source (0x80-0xFF) ; (psm + src LE)
#    => le kernel passe le canal en L2CAP_MODE_LE_FLOWCTL des le bind.
s.bind((socket.BDADDR_ANY, 0, 0, ADDR_TYPE))

# 2) assertion : doit afficher OK maintenant
s.setsockopt(socket.SOL_BLUETOOTH, socket.BT_MODE, struct.pack("B", socket.BT_MODE_LE_FLOWCTL))
print("[client] BT_MODE = LE_FLOWCTL OK", flush=True)

# 3) sécurité, puis connect
s.setsockopt(socket.SOL_BLUETOOTH, socket.BT_SECURITY, struct.pack("BB", socket.BT_SECURITY_MEDIUM, 0))
s.connect((SERVER_ADDR, PSM, 0, ADDR_TYPE))
print("[client] connected", flush=True)

for i in range(3):
    n = s.send(f"MSG-{i} from client".encode())
    print(f"[client] sent #{i}: {n} bytes", flush=True)
    resp = s.recv(1024)
    print(f"[client] echo: {resp!r}", flush=True)
    time.sleep(1)

s.close()
print("[client] closed", flush=True)
