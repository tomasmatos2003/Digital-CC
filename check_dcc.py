from PyKCS11 import PyKCS11, Mechanism, CKM_SHA1_RSA_PKCS
from PyKCS11.LowLevel import *
import sys
import json
from pyasn1.codec.der.decoder import decode
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import hashlib
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from PIL import Image
import io
import base64


lib = '/usr/local/lib/libpteidpkcs11.so' 
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)

def create_commitment(attribute_name, attribute_value, mask):
    combined = f"{attribute_name}{attribute_value}{mask}".encode()
    return hashlib.sha1(combined).hexdigest()

def verify_signature(public_key_pem, data_to_verify, signature):
   
    try:
        # Load the public key from PEM format
        public_key = load_pem_public_key(public_key_pem.encode('utf-8'))

        public_key.verify(
            signature,
            data_to_verify,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False



def validate_issuer_signature(issuer_sign, issuer_cert, dcc_data):
 
    try:
        issuer_signature = bytes.fromhex(issuer_sign)  
        issuer_cert_pem = issuer_cert.encode('utf-8') 

        issuer_cert = load_pem_x509_certificate(issuer_cert_pem)
        issuer_public_key = issuer_cert.public_key()

        only_commitment = []
        for comi in dcc_data["commitment"]:
            only_commitment.append(comi)
        only_commitment.append(dcc_data["public_key"])

        serialized_only_commitment = json.dumps(only_commitment, separators=(',', ':')).encode('utf-8')

        # Hash the data before verifying the signature
        digest = hashes.Hash(hashes.SHA512())
        digest.update(serialized_only_commitment)
        hashed_data = digest.finalize()

        # Verify the signature
        issuer_public_key.verify(
            issuer_signature,
            hashed_data,
            padding.PKCS1v15(),
            Prehashed(hashes.SHA512())
        )
        return True

    except Exception as e:
        print(f"Failed to validate issuer's signature: {e}")
        return False
    

def display_image(base64_string):
    try:
        image_bytes = base64.b64decode(base64_string)        
        image = Image.open(io.BytesIO(image_bytes))
        image.show()
    
    except Exception as e:
        print(f"Error displaying image: {e}")


def main_menu():

    dcc_data = {}
    while True:

        print("\n==== check_dcc Application ====")
        print("1. Load dcc min")
        print("2. Validate issuer_signature")
        print("3. Validate owner_signature")
        print("4. Validate commitments")
        print("5. Check data")
        print("6. Exit")
        choice = input("Choose an option (1-4): ")
          
        if choice == "1":

            try:
                json_name = input("-- Load a DCC (json): ").strip()

                with open("min_dccs/"+json_name, 'r') as json_file:
                    dcc_data = json.load(json_file)
            except FileNotFoundError:
                print(f"File '{json_name}' not found. Please try again.")
            except json.JSONDecodeError:
                print("Failed to parse JSON. Ensure the file is a valid DCC JSON.")
                
            except Exception as e:
                print(f"Error during minimal DCC generation: {e}")
                
    
        elif choice == "2":
            if dcc_data == {}:
                print("Need to load dcc_min!!")
                continue

          
            issuer_sign = dcc_data["issuer_signature"]["value"]
            issuer_cert = dcc_data["issuer_signature"]["certificate"]

            verify_issuer = validate_issuer_signature(issuer_sign, issuer_cert, dcc_data)

            if verify_issuer:
                print("DCC is valid and signed by the trusted issuer.")

            else:
                print("DCC validation failed or issuer signature is invalid.")   
           
        elif choice == "3":
            if dcc_data == {}:
                print("Need to load dcc_min!!")
                continue

            signature = dcc_data["owner_signature"]["value"]
            public_key_data = dcc_data["public_key"]["value"]
            
            dcc_without_signature = {key: dcc_data[key] for key in dcc_data if key != "owner_signature"}

            serialized_data = json.dumps(dcc_without_signature).encode('utf-8')

            is_valid = verify_signature(public_key_data, serialized_data, bytes.fromhex(signature))
            if not is_valid:
                print("Signature verification failed. Data integrity compromised.")
            else:
                print("Signature verified successfully. Data integrity intact.")
        
        elif choice == "4":

            if dcc_data == {}:
                print("Need to load dcc_min!!")
                continue

            commitments = dcc_data["commitment"]
            attributes = dcc_data["identity_attributes"]

            are_included = True
            for at in attributes:
                value = at["value"][0]
                mask = at["value"][1]
                label = at["label"]
                commit = create_commitment(label, value, mask)
                
                if commit not in commitments:
                    print("Changed -> ", value, " (value) or ", label, " (label) or ", mask , " (mask) ")
                    are_included = False

            if are_included:
                print("Data integrity intact.")
            else :
                print("Data integrity compromised.")


        elif choice == "5":
            if dcc_data == {}:
                print("Need to load dcc_min!!")
                continue

            attributes = dcc_data["identity_attributes"]

            for at in attributes:
                value = at["value"][0]
                label = at["label"]

                if label == "image_bytes":
                    display_image(value)
                    continue

                print(label, ": ", value)


        elif choice == "6":
            print("Exiting the program. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice. Please choose a valid option.")

if __name__ == "__main__":
    main_menu()
