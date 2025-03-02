import requests
import json

def get_challenge():
    response = requests.get("http://localhost:5000/challenge")
    return bytes.fromhex(response.json()["challenge"])

def decrypt(ciphertext):
    response = requests.post("http://localhost:5000/decrypt", json={"ciphertext": ciphertext.hex()})
    return bytes.fromhex(response.json()["plaintext"])

def verify(plaintext):
    response = requests.post("http://localhost:5000/verify", json={"plaintext": plaintext.hex()})
    return response.json()["response"]

def exploit():
    challenge_ct = get_challenge()
    recovered_pt = decrypt(challenge_ct)
    flag = verify(recovered_pt)
    print("Recovered string.txt content:", flag)

if __name__ == "__main__":
    exploit()
