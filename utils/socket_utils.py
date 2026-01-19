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
    
def send_all(conn, data: bytes):
    """Send all bytes reliably."""
    total_sent = 0
    while total_sent < len(data):
        sent = conn.send(data[total_sent:])
        if sent == 0:
            raise RuntimeError("Socket connection broken")
        total_sent += sent