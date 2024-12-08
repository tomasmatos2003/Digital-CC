from PyKCS11 import PyKCS11, Mechanism, CKM_SHA1_RSA_PKCS
from PyKCS11.LowLevel import *
import sys
import json
from pyasn1.codec.der.decoder import decode
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import load_pem_public_key


lib = '/usr/local/lib/libpteidpkcs11.so' 
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)

def create_commitment(attribute_name, attribute_value, mask):
    combined = f"{attribute_name}{attribute_value}{mask}".encode()
    return hashlib.sha256(combined).hexdigest()

def verify_signature(public_key_pem, data_to_verify, signature):
    """
    Verifies the signature of the data using the provided public key.

    Args:
        public_key_pem (str): PEM-encoded public key.
        data_to_verify (bytes): The serialized data to verify (in bytes).
        signature (bytes): The signature to verify (in bytes).

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        # Load the public key from PEM format
        public_key = load_pem_public_key(public_key_pem.encode('utf-8'))

        # Verify the signature using SHA256 and PKCS1v15 padding
        public_key.verify(
            signature,
            data_to_verify,
            PKCS1v15(),
            SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False


    
def derive_mask(password, attribute_name):
    return hashlib.sha256(f"{password}{attribute_name}".encode()).hexdigest()


def validate_issuer_signature(issuer_sign, issuer_cert, dcc_data):
    """
    Validate the issuer's signature using the issuer's public key extracted from the certificate.
    """
    try:
        # Extract data to validate
        issuer_signature = bytes.fromhex(issuer_sign)  # Convert hex signature back to bytes
        issuer_cert_pem = issuer_cert.encode('utf-8')  # Certificate as PEM string

        # Extract public key from issuer's certificate
        issuer_cert = load_pem_x509_certificate(issuer_cert_pem)
        issuer_public_key = issuer_cert.public_key()

        only_commitment = []
        for comi in dcc_data["commitment"]:
            only_commitment.append(comi)
        only_commitment.append(dcc_data["public_key"])

        serialized_only_commitment = json.dumps(only_commitment, separators=(',', ':')).encode('utf-8')

        # Hash the data before verifying the signature
        digest = hashes.Hash(hashes.SHA256())
        digest.update(serialized_only_commitment)
        hashed_data = digest.finalize()

        # Verify the signature
        issuer_public_key.verify(
            issuer_signature,
            hashed_data,
            padding.PKCS1v15(),
            Prehashed(hashes.SHA256())
        )
        return True

    except Exception as e:
        print(f"Failed to validate issuer's signature: {e}")
        return False
    

def sign_with_cc(data_to_sign):
    """
    Signs data using the Citizen Card's authentication key to verify possession.
    """

    slots = pkcs11.getSlotList()

    for slot in slots:
        token_info = pkcs11.getTokenInfo(slot)
        if 'CARTAO DE CIDADAO' in token_info.label:
            session = pkcs11.openSession(slot)
            try:
                priv_key = session.findObjects([
                    (CKA_CLASS, CKO_PRIVATE_KEY),
                    (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
                ])[0]

                mechanism = Mechanism(CKM_SHA1_RSA_PKCS)
                signature = session.sign(priv_key, data_to_sign, mechanism)
                session.closeSession()

                return bytes(signature), datetime.now(timezone.utc).isoformat()
            except Exception as e:
                session.closeSession()
                raise Exception(f"Failed to sign data: {e}")

    raise Exception("Citizen Card not found or private key not accessible.")




def main_menu():

    dcc_data = {}
    while True:

        print("\n==== check_dcc Application ====")
        print("1. Load dcc min")
        print("2. Validate issuer_signature")
        print("3. Validate owner_signature")
        print("4. Validate commitments")
        print("5. Exit")
        choice = input("Choose an option (1-4): ")
          
        if choice == "1":

            try:
                json_name = input("-- Load a DCC (json): ").strip()
                #json_name = "dcc_min.json" 
                with open(json_name, 'r') as json_file:
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
                commit = create_commitment(label, value, mask )
                
                if commit not in commitments:
                    print("Changed -> ", commit)
                    are_included = False

            if are_included:
                print("Data integrity intact.")
            else :
                print("Data integrity compromised.")




        elif choice == "5":
            print("Exiting the program. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice. Please choose a valid option.")

if __name__ == "__main__":
    main_menu()
