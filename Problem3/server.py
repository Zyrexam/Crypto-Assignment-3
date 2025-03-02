from flask import Flask, request, jsonify
import os
import binascii

app = Flask(__name__)

SECRET_FILE = "Secret/string.txt"

def encrypt_command(command):
    """Mock encryption: Convert command to hex."""
    return binascii.hexlify(command.encode()).decode()

def decrypt_command(encrypted_hex):
    """Mock decryption: Convert hex back to command."""
    try:
        return binascii.unhexlify(encrypted_hex).decode()
    except binascii.Error:
        return None

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    command = data.get("command", "")
    encrypted = encrypt_command(command)
    return jsonify({"encrypted": encrypted})

@app.route("/run", methods=["POST"])
def run():
    data = request.get_json()
    encrypted_hex = data.get("encrypted_hex", "")
    command = decrypt_command(encrypted_hex)

    if not command:
        return jsonify({"output": "Invalid command"})

    # Prevent access to sensitive files
    if "string.txt" in command:
        return jsonify({"output": "I won't run that."})

    try:
        output = os.popen(command).read().strip()
    except Exception as e:
        output = str(e)

    return jsonify({"output": output})

@app.route("/bitflip", methods=["POST"])
def bit_flip():
    """Flip a bit at a given position in the encrypted command."""
    data = request.get_json()
    encrypted_hex = data.get("encrypted_hex", "")
    position = int(data.get("position", 0))
    bit = int(data.get("bit", 0))

    bytes_data = bytearray.fromhex(encrypted_hex)
    if position < len(bytes_data):
        bytes_data[position] ^= (1 << bit)

    return jsonify({"modified": bytes_data.hex()})

@app.route("/bytexor", methods=["POST"])
def byte_xor():
    """XOR a byte at a given position."""
    data = request.get_json()
    encrypted_hex = data.get("encrypted_hex", "")
    position = int(data.get("position", 0))
    value = int(data.get("value", 0))

    bytes_data = bytearray.fromhex(encrypted_hex)
    if position < len(bytes_data):
        bytes_data[position] ^= value

    return jsonify({"modified": bytes_data.hex()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
