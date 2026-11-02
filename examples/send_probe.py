"""Generate a single synthetic status probe against the local demo only."""
import socket
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from sentinel import write_varint, packet
host=b'localhost'
handshake=write_varint(770)+write_varint(len(host))+host+(25599).to_bytes(2,'big')+write_varint(1)
if __name__=='__main__':
    with socket.create_connection(('127.0.0.1',25599),timeout=5) as s:
        s.sendall(packet(0,handshake)+packet(0,b''))
        print('Status response bytes:',len(s.recv(4096)))
