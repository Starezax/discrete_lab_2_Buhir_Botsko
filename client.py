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

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
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

    def rsa_encrypt(self, m_int, pub): 
        return pow(m_int, pub[0], pub[1])

    def rsa_decrypt(self, c_int, priv): 
        return pow(c_int, priv[0], priv[1])

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
            outp.extend(m_int.to_bytes(size, 'big'))
        return outp.decode('utf-8')

    def init_connection(self):
        self.generate_keys()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print(f"[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())
        self.server_public_key = tuple(json.loads(self.s.recv(1024).decode()))
        self.s.send(json.dumps(self.public_key).encode())

        print(f"[{self.username}]: connected")

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()
    
    def read_handler(self): 
        while True:
            message = self.s.recv(8192).decode()
            if not message:
                break
            payload = json.loads(message)
            decrypted_msg = self.decrypt_message(payload['message'], self.private_key)
            if hashlib.sha256(decrypted_msg.encode()).hexdigest() != payload['hash']:
                print("Hashes are not the same, no integrity")
                continue
            print(decrypted_msg)

    def write_handler(self):
        while True:
            message = input()
            h = hashlib.sha256(message.encode()).hexdigest()
            encrypted_msg = self.encrypt_message(message, self.server_public_key)
            self.s.send(json.dumps({'hash': h, 'message': encrypted_msg}).encode())

        

if __name__ == '__main__':
    nickname = input("Enter your nickname: ")
    cl = Client("127.0.0.1", 9001, nickname)
    cl.init_connection()