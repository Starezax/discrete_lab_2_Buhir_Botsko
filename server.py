#pylint:skip-file

import socket
import threading
import random
import math
import json
import hashlib

def compute_small_primes():
    limit = 10_000_000
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = bytearray([0, 0])
    for i in range(2, int(math.isqrt(limit)) + 1):
        if sieve[i]:
            sieve[i*i::i] = bytearray(len(sieve[i*i::i]))
    return [i for i, is_prime in enumerate(sieve) if is_prime]

def is_prime(num, k=5):
    d, s = num - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randint(2, num - 1)
        x = pow(a, d, num)
        if x in (1, num - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, num)
            if x == num - 1:
                break
        else:
            return False
    return True

def generate_large_prime():
    start, end = 10**12 + 1, 10**15
    small_primes = compute_small_primes()
    while True:
        outp = random.randint(start, end)
        if all(outp % small_prime for small_prime in small_primes if small_prime * small_prime <= outp) and is_prime(outp):
            return outp


class Server:
    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.client_keys = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.generate_keys()

    def generate_keys(self):
        p, q = generate_large_prime(), generate_large_prime()
        while p == q:
            q = generate_large_prime()
        n = p * q
        phi = (p - 1) * (q - 1)
        e = random.randrange(2, phi)
        while math.gcd(e, phi) != 1:
            e = random.randrange(2, phi)
        d = pow(e, -1, phi)
        self.public_key = (e, n)
        self.private_key = (d, n)

    def rsa_encrypt(self, message_int: int, public_key: tuple) -> int:
        e, n = public_key
        return pow(message_int, e, n)

    def rsa_decrypt(self, cipher_int: int, private_key: tuple) -> int:
        d, n = private_key
        return pow(cipher_int, d, n)

    def encrypt_message(self, message: str, public_key: tuple) -> str:
        e, n = public_key
        msg_bytes = message.encode('utf-8')
        max_len = (n.bit_length() - 1) // 8
        chunks = [msg_bytes[i:i+max_len] for i in range(0, len(msg_bytes), max_len)]
        outp = []
        for chunk in chunks:
            m_int = int.from_bytes(chunk, 'big')
            c_int = pow(m_int, e, n)
            outp.append(str(c_int))
        return json.dumps(outp)

    def decrypt_message(self, encrypted_message: str, private_key: tuple) -> str:
        d, n = private_key
        encrypted_chunks = json.loads(encrypted_message)
        outp = bytearray()
        for c_str in encrypted_chunks:
            c_int = int(c_str)
            m_int = pow(c_int, d, n)
            size = (m_int.bit_length() + 7) // 8
            chunk = m_int.to_bytes(size, 'big')
            outp.extend(chunk)
        return outp.decode('utf-8')

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)
        print(f"Server started")

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} connected from {addr}")

            self.username_lookup[c] = username
            self.clients.append(c)
            c.send(json.dumps(self.public_key).encode())
            client_pub = tuple(json.loads(c.recv(1024).decode()))
            self.client_keys[c] = client_pub

            threading.Thread(target=self.handle_client, args=(c,)).start()

    def broadcast(self, msg: str, sender=None):
        for client in self.clients:
            if client != sender:
                pub = self.client_keys[client]
                enc = self.encrypt_message(msg, pub)
                h = hashlib.sha256(msg.encode()).hexdigest()
                payload = json.dumps({'hash': h, 'message': enc})
                client.send(payload.encode())

    def handle_client(self, c):
        while True:
            msg = c.recv(4096).decode()
            if not msg:
                break
            payload = json.loads(msg)
            hy = payload['hash']
            enc = payload['message']
            dec = self.decrypt_message(enc, self.private_key)
            if hashlib.sha256(dec.encode()).hexdigest() != hy:
                print("Hashes are not the same, no integrity")
                continue
            msg = f"{self.username_lookup[c]} says: {dec}"
            self.broadcast(msg, sender=c)
        c.close()


if __name__ == "__main__":
    s = Server(9001)
    s.start()
