from flask import Flask, request, jsonify
import os
import random
from Crypto.Cipher import DES3

app = Flask(__name__)

class Functional_Des:
    def __init__(self):
        self.key = os.urandom(24)
        self.iv = os.urandom(8)
        self.flipped_bits = set(range(0, 192, 8))
        self.challenge = os.urandom(64)
        self.counter = 128

    def get_challenge(self):
        cipher = DES3.new(self.key, mode=DES3.MODE_CBC, iv=self.iv)
        return cipher.encrypt(self.challenge)

    def alter_key(self):
        if len(self.flipped_bits) == 192:
            self.flipped_bits = set(range(0, 192, 8))
        remaining = list(set(range(192)) - self.flipped_bits)
        num_flips = random.randint(1, len(remaining))
        self.flipped_bits = self.flipped_bits.union(
            random.choices(remaining, k=num_flips))
        mask = int.to_bytes(sum(2**i for i in self.flipped_bits), 24, byteorder="big")
        return bytes(i ^ j for i, j in zip(self.key, mask))

    def decrypt(self, text: bytes):
        self.counter -= 1
        if self.counter < 0:
            return b''
        key = self.alter_key()
        if len(text) % 8 != 0:
            return b''
        cipher = DES3.new(key, mode=DES3.MODE_CBC, iv=self.iv)
        return cipher.decrypt(text)

    def get_random_string(self, plain):
        if plain == self.challenge:
            with open("string.txt", "rb") as f:
                FLAG = f.read()
            return FLAG
        return b"Incorrect plaintext"

chall = Functional_Des()

@app.route("/challenge", methods=["GET"])
def fetch_challenge():
    return jsonify({"challenge": chall.get_challenge().hex()})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    ct = bytes.fromhex(request.json.get("ciphertext"))
    return jsonify({"plaintext": chall.decrypt(ct).hex()})

@app.route("/verify", methods=["POST"])
def verify():
    pt = bytes.fromhex(request.json.get("plaintext"))
    return jsonify({"response": chall.get_random_string(pt).decode(errors='ignore')})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
