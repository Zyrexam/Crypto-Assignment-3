#!/usr/bin/env python3
import socket
import sys
from Crypto.Cipher import DES3

def connect_to_server(host="localhost", port=12345):
    """Establish connection to the server"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        return s
    except Exception as e:
        print(f"Connection error: {e}")
        sys.exit(1)

class RemoteInteraction:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""
        
    def recv_until(self, delimiter=b"\n"):
        """Receive data until a delimiter is found"""
        while delimiter not in self.buffer:
            data = self.sock.recv(4096)
            if not data:
                return b""
            self.buffer += data
            
        line, self.buffer = self.buffer.split(delimiter, 1)
        return line + delimiter
    
    def fetch_challenge(self):
        """Get the encrypted challenge from the server"""
        self.sock.sendall(b"1\n")
        response = self.recv_until()
        while b"Choose an API option" not in response:
            response += self.recv_until()
        
        # Extract hex challenge from the response
        lines = response.split(b'\n')
        for line in lines:
            if b"Choose an API option" not in line and line.strip():
                encrypted_challenge_hex = line
                break
        
        return bytes.fromhex(encrypted_challenge_hex.decode())
    
    def decrypt(self, ciphertext):
        """Send ciphertext to be decrypted by the server"""
        hex_ct = ciphertext.hex().encode()
        self.sock.sendall(b"2\n")
        self.recv_until(b": ")  # Wait for the prompt
        self.sock.sendall(hex_ct + b"\n")
        
        response = self.recv_until()
        while b"Choose an API option" not in response:
            response += self.recv_until()
        
        # Extract the decrypted text
        lines = response.split(b'\n')
        for line in lines:
            if b"Choose an API option" not in line and line.strip():
                decrypted_hex = line
                return bytes.fromhex(decrypted_hex.decode())
        
        return None
    
    def reveal_flag(self, challenge_plaintext):
        """Submit the recovered plaintext to get the flag"""
        hex_pt = challenge_plaintext.hex().encode()
        self.sock.sendall(b"3\n")
        self.recv_until(b": ")  # Wait for the prompt
        self.sock.sendall(hex_pt + b"\n")
        
        response = self.recv_until()
        while b"Choose an API option" not in response and b"Not quite right" not in response:
            data = self.sock.recv(4096)
            if not data:
                break
            response += data
        
        return response

def recover_challenge(remote):
    """
    The main recovery algorithm. It exploits the bit-flipping pattern in 
    the key to recover the original challenge plaintext.
    """
    # Get the encrypted challenge
    encrypted_challenge = remote.fetch_challenge()
    
    # Create a dictionary to track potential byte values at each position
    possible_bytes = {}
    
    # We need to recover the challenge byte by byte
    challenge_length = 64
    recovered_challenge = bytearray(challenge_length)
    
    # Track the bytes we've already tried to decrypt for each position
    tested_combinations = {}
    
    print("[*] Starting challenge recovery...")
    
    # We have 128 decrypt operations available
    for attempt in range(120):  # Reserve a few operations for safety
        # Choose a position to work on - prioritize ones we haven't solved yet
        unsolved_positions = [i for i in range(challenge_length) if i not in possible_bytes or len(possible_bytes[i]) > 1]
        
        if not unsolved_positions:
            print("[+] All positions have candidate values!")
            break
            
        position = unsolved_positions[0]
        block_index = position // 8
        
        # Get the block we want to attack
        target_block = encrypted_challenge[block_index*8:(block_index+1)*8]
        
        # We'll try multiple decryptions to gather data
        decrypted = remote.decrypt(target_block)
        
        # Record this result if we haven't seen it before
        if position not in tested_combinations:
            tested_combinations[position] = {}
            
        # Store the decryption result
        combo_key = decrypted.hex()
        if combo_key not in tested_combinations[position]:
            tested_combinations[position][combo_key] = decrypted[position % 8]
            
        # Update possible values for this position
        if position not in possible_bytes:
            possible_bytes[position] = set()
            
        possible_bytes[position].add(decrypted[position % 8])
        
        # If we've found a single value for this position, update our challenge
        if len(possible_bytes[position]) == 1:
            recovered_challenge[position] = list(possible_bytes[position])[0]
            print(f"[+] Position {position} recovered: {recovered_challenge[position]:02x}")
            
        # If we're not making progress on this position, move to the next one
        if len(tested_combinations[position]) >= 10:
            # If we have multiple candidates, choose the most common one
            if position not in possible_bytes or len(possible_bytes[position]) > 1:
                value_counts = {}
                for val in tested_combinations[position].values():
                    if val not in value_counts:
                        value_counts[val] = 0
                    value_counts[val] += 1
                
                most_common = max(value_counts.items(), key=lambda x: x[1])[0]
                recovered_challenge[position] = most_common
                print(f"[+] Position {position} best guess: {recovered_challenge[position]:02x}")
    
    print("[*] Challenge recovery complete!")
    print(f"[*] Recovered challenge: {recovered_challenge.hex()}")
    
    return bytes(recovered_challenge)

def main():
    # Parse command line arguments
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
    else:
        host = "localhost"
        port = 12345
    
    print(f"[*] Connecting to {host}:{port}")
    sock = connect_to_server(host, port)
    remote = RemoteInteraction(sock)
    
    try:
        # Recover the challenge
        challenge_plaintext = recover_challenge(remote)
        
        # Submit the challenge to get the flag
        print("[*] Submitting recovered challenge to get the flag...")
        flag = remote.reveal_flag(challenge_plaintext)
        
        print("[+] FLAG:", flag.decode().strip())
        
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()