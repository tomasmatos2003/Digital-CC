import socket
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import time
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.hashes import Hash
from datetime import datetime, timezone

def load_issuer_private_key(private_key_path):
    """
    Load the issuer's private key from the PEM file.
    """
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # Add password if the key is encrypted
        )
    return private_key

def load_issuer_certificate(cert_path):
    """
    Load the issuer's self-signed certificate from the PEM file.
    """
    with open(cert_path, "rb") as cert_file:
        certificate = load_pem_x509_certificate(cert_file.read())
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

def sign_with_issuer_key(private_key, data_to_sign):
    """
    Sign data using the issuer's private key.
    """

    # Hash the data first
    digest = Hash(hashes.SHA256())
    digest.update(data_to_sign)
    hashed_data = digest.finalize()

    signature = private_key.sign(
        hashed_data,
        padding.PKCS1v15(),
        Prehashed(hashes.SHA256())
    )

    full_sign = {
        "value": signature.hex(),  # Convert binary signature to hex
        "timestamp": datetime.now(timezone.utc).isoformat(),  # Current UTC timestamp
        "description": "Issuer signature using SHA-256 and RSA-PKCS1v1.5"
    }

    return full_sign

def start_server():
    host = '127.0.0.1'  
    port = 65432       

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port}...")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected by {addr}")
                
                buffer = b""
                
                while True:
                    data = conn.recv(1024)
                    
                    if not data:  # If no data, the client has closed the connection
                        break
                    
                    buffer += data  # Append the received data to the buffer

                    # Attempt to parse the complete JSON if possible
                    try:
                        json_data = json.loads(buffer.decode('utf-8'))
                        # print(f"Received data: {json_data["dcc"]}")
                        print("Received pré-dcc sucessfully")


                        # Write the 'dcc' part into a JSON file
                        dcc_data = json_data["dcc"]


                        # Sign the DCC using issuer's private key
                        issuer_private_key = load_issuer_private_key('dcc_issuer/private_key.pem')

                        only_commitment = []
                        for att in dcc_data["identity_attributes"]:
                            only_commitment.append(att["commitment"])
                        only_commitment.append(dcc_data["public_key"])
                        serialized_only_commitment = json.dumps(only_commitment, separators=(',', ':')).encode('utf-8')

                        issuer_signature = sign_with_issuer_key(issuer_private_key, serialized_only_commitment)
                            
                        # Load issuer's self-signed certificate
                        issuer_cert = load_issuer_certificate('dcc_issuer/self_signed_certificate.pem')

                        dcc_data["issuer_signature"] = issuer_signature
                        dcc_data["issuer_signature"]["certificate"] = issuer_cert
                            # Update response with issuer's signature and certificate
                        response = {
                            "status": "success",
                            "type" : "dcc_complete",
                            "dcc": dcc_data
                        }

                        # Send the response back to the client
                        conn.sendall(json.dumps(response, default=str).encode('utf-8'))
                        # print(f"Sent response: {response}")
                        print("Sent final dcc sucessfully")

                        break  # Break after processing the full message

                    except json.JSONDecodeError:
                        # If JSON is incomplete, continue receiving data
                        continue
                print("Connection closed.")
            
if __name__ == "__main__":
    print("\n==== gen_dcc Application ====")

    start_server()
