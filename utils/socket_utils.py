def recv_all(conn, n):
    """Receive exactly n bytes from conn, blocking until done"""
    data = b""
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_resp(conn, msg: bytes):
    conn.send(len(msg).to_bytes(8, "big"))
    conn.send(msg)