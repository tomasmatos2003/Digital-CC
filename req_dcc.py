from PyKCS11 import PyKCS11
from PyKCS11.LowLevel import *
import sys
import socket
import json
from pyasn1.codec.der.decoder import decode
import hashlib
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import subprocess
import re


lib = '/usr/local/lib/libpteidpkcs11.so' 
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)


gen_dcc_host = '127.0.0.1'  
gen_dcc_port = 65432       


def create_dcc(cc_data):
    

    def derive_mask(password, attribute_name):
        return hashlib.sha1(f"{password}{attribute_name}".encode()).hexdigest()

    def create_commitment(attribute_name, attribute_value, mask):
        combined = f"{attribute_name}{attribute_value}{mask}".encode()
        return hashlib.sha1(combined).hexdigest()

    # password = "securepassword"
    password = input("-- Insert a secret: ")
    commitments = []

    for label, value in cc_data.items():
        if value is None or label == "public_key_pem" or label == "key_size":
            continue
        mask = derive_mask(password, label)
    
        commitment = create_commitment(label, value, mask)
        commitments.append({
            "label":label,
            "value": value,
            "commitment": commitment
        })

    dcc = {
        "identity_attributes": commitments,
        "digest_function": "SHA-1",
        "public_key": {
            "value": cc_data["public_key_pem"],
            "key_size": cc_data["key_size"]
        }
    }

    return dcc


def run_java_program():
    try:
        compile_command = ["javac", "-cp", "/usr/local/lib/pteidlibj.jar", "CcData.java"]
        subprocess.run(compile_command, check=True)
        
        run_command = [
            "java",
            "-cp",
            ".:/usr/local/lib/pteidlibj.jar",
            "-Djava.library.path=/usr/local/lib",
            "CcData"
        ]
        result = subprocess.run(run_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        return result.stdout.decode("utf-8"), result.stderr.decode("utf-8")
    
    except subprocess.CalledProcessError as e:
        print(f"Error during Java program execution:\n{e.stderr.decode('utf-8')}")
        return None, e.stderr.decode("utf-8")

def extract_data(output):

    data_patterns = {
        "name": r"^Name:\s+([^\n]+)",  
        "surname": r"^Surname:\s+([^\n]+)", 
        "document_number": r"^Document Number:\s+([^\n]+)",
        "gender": r"^Gender:\s+([^\n]+)",
        "date_of_birth": r"^Date of Birth:\s+([^\n]+)",
        "document_version": r"^Document Version:\s+([^\n]+)",
        "document_type": r"^Document Type:\s+([^\n]+)",
        "validity_start_date": r"^Validity Start Date:\s+([^\n]+)",
        "nationality": r"^Nationality:\s+([^\n]+)",
        "document_pan": r"^Document PAN:\s+([^\n]+)",
        "validity_end_date": r"^Validity End Date:\s+([^\n]+)",
        "height": r"^Height:\s+([^\n]+)",
        "civilian_id_number": r"^Civilian ID Number:\s+([^\n]+)",
        "tax_number": r"^Tax Number:\s+([^\n]+)",
        "social_security_number": r"^Social Security Number:\s+([^\n]+)",
        "health_number": r"^Health Number:\s+([^\n]+)",
        "issuing_entity": r"^Issuing Entity:\s+([^\n]+)",
        "local_of_request": r"^Local of Request:\s+([^\n]+)",
        "father_name": r"^Father's Name:\s+([^\n]+)",
        "mother_name": r"^Mother's Name:\s+([^\n]+)",
        "parents": r"^Parents:\s+([^\n]+)",
        "public_key_pem": r"Public Key\s?:\s+(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)",
        "key_size": r"Key Size:\s+(\d+)\s+bits",
        "image_bytes": r"^Image bytes\s+(.+)" 
    }
    
    extracted_data = {}
    for key, pattern in data_patterns.items():
        match = re.search(pattern, output, re.DOTALL | re.MULTILINE)
        if match:
            extracted_data[key] = match.group(1).strip()
        else:
            extracted_data[key] = None 
    
    return extracted_data
 
def get_portuguese_cc_data():

    stdout, stderr = run_java_program()
    
    if stdout:
     
        extracted_data = extract_data(stdout)
        return extracted_data
                
    else:
        print("Failed to execute the Java program.")
        print(stderr)
        return None



def send_receive_dictionary(dictionary):

    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((gen_dcc_host, gen_dcc_port))
            message = json.dumps(dictionary, default=str)
            client_socket.sendall(message.encode('utf-8'))
           
            print("Sent pré-dcc sucessfully")

            buffer = b""
            while True:
                chunk = client_socket.recv(1024)  
                if not chunk:  
                    break
                buffer += chunk

            response_dict = json.loads(buffer.decode('utf-8'))

            print("Received final dcc sucessfully")

            return response_dict

    except Exception as e:
        print(f"Error during authentication: {e}")

def validate_issuer_signature(issuer_sign, issuer_cert, dcc_data):
    
    try:
        issuer_signature = bytes.fromhex(issuer_sign)  
        issuer_cert_pem = issuer_cert.encode('utf-8') 

        # Extract public key from issuer's certificate
        issuer_cert = load_pem_x509_certificate(issuer_cert_pem)
        issuer_public_key = issuer_cert.public_key()

        only_commitment = []
        for att in dcc_data["identity_attributes"]:
            only_commitment.append(att["commitment"])
        only_commitment.append(dcc_data["public_key"])

        serialized_only_commitment = json.dumps(only_commitment, separators=(',', ':')).encode('utf-8')
        
        # Hash the data before verifying the signature
        digest = hashes.Hash(hashes.SHA512())
        digest.update(serialized_only_commitment)
        hashed_data = digest.finalize()

        issuer_public_key.verify(
            issuer_signature,
            hashed_data,
            padding.PKCS1v15(),
            Prehashed(hashes.SHA512())
        )

        print("Issuer's signature is valid. Data integrity verified.")
        return True

    except Exception as e:
        print(f"Failed to validate issuer's signature: {e}")
        return False
    

def main_menu():
    while True:
        print("\n==== req_dcc Application ====")
        print("1. Request a DCC")
        print("2. Exit")
        choice = input("Choose an option (1-2): ")

        if choice == "1":
            try:
                cc_data = get_portuguese_cc_data()
                if cc_data == None:
                    continue

                dcc = create_dcc(cc_data)
                message = {"type": "request", "dcc": dcc}
                
                response = send_receive_dictionary(message)
                final_dcc = response["dcc"]

                issuer_sign = final_dcc["issuer_signature"]["value"]
                issuer_cert = final_dcc["issuer_signature"]["certificate"]
                verify_issuer = validate_issuer_signature(issuer_sign, issuer_cert, final_dcc)

                if verify_issuer:
                    print("DCC is valid and signed by the trusted issuer.")

                    with open(f'dccs/dcc_{final_dcc['identity_attributes'][12]['value']}.json', 'w') as json_file:
                        json.dump(final_dcc, json_file, indent=4)

                else:
                    print("DCC validation failed or issuer signature is invalid.")
                    
               
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "2":
            print("Exiting the program. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice. Please choose a valid option.")

if __name__ == "__main__":
    main_menu()
