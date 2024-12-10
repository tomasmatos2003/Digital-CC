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
from datetime import datetime, timezone


lib = '/usr/local/lib/libpteidpkcs11.so' 
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)

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
        for att in dcc_data["identity_attributes"]:
            only_commitment.append(att["commitment"])
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

        print("Issuer's signature is valid. Data integrity verified.")
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

                mechanism = Mechanism(CKM_SHA256_RSA_PKCS)
                signature = session.sign(priv_key, data_to_sign, mechanism)
                session.closeSession()

                return bytes(signature), datetime.now(timezone.utc).isoformat()
            except Exception as e:
                session.closeSession()
                raise Exception(f"Failed to sign data: {e}")

    raise Exception("Citizen Card not found or private key not accessible.")


def main_menu():
    while True:
        print("\n==== gen_min_dcc Application ====")
        print("1. Generate min DCC from DCC")
        print("2. Exit")
        choice = input("Choose an option (1-2): ")

        if choice == "1":
            try:
                json_name = input("     Load a DCC (json): ").strip()
                with open(json_name, 'r') as json_file:
                    dcc_data = json.load(json_file)
                
                print("DCC loaded successfully.")

                issuer_sign = dcc_data["issuer_signature"]["value"]
                issuer_cert = dcc_data["issuer_signature"]["certificate"]

                verify_issuer = validate_issuer_signature(issuer_sign, issuer_cert, dcc_data)

                if verify_issuer:
                    print("DCC is valid and signed by the trusted issuer.")

                    attributes = dcc_data["identity_attributes"]
                    labels = [dic["label"] for dic in attributes]

                    to_remove = [] 
                    for label in labels:
                        response = input(f"  Remove attribute '{label}'? (y/n)").strip()
                        if response.lower() == "y":
                            to_remove.append(label)

                    new_labels = [label for label in labels if label not in to_remove]

                    if new_labels == []:
                        print("Need at least one attribute!!")
                        continue
                    elif len(new_labels) == len(labels):
                        print("Need at least to remove one!!")
                        continue

                    dcc_min = {}
                    only_commitment = []
                    for att in dcc_data["identity_attributes"]:
                        only_commitment.append(att["commitment"])

                    dcc_min["commitment"] = only_commitment
                    dcc_min["digest_function"] = dcc_data["digest_function"]
                    
                    pseudo_random_password = "securepassword"
                    attributes = [{"label":dic["label"], "value": (dic["value"], derive_mask(pseudo_random_password, dic["label"]))} for dic in attributes if dic["label"] in new_labels]
                    dcc_min["identity_attributes"] = attributes
                    dcc_min["public_key"] = dcc_data["public_key"]
                    dcc_min["issuer_signature"] = dcc_data["issuer_signature"]
                    dccmin_data_to_sign = json.dumps(dcc_min).encode('utf-8')

                    signature, timestamp = sign_with_cc(dccmin_data_to_sign)

                    dcc_min["owner_signature"] = {
                        "value": signature.hex(),  
                        "timestamp" : timestamp,
                        "description": "RSA with SHA-1 PKCS#1 v1.5, using the Citizen Card private key for signing."  
                    }
                    with open(f'dcc_min.json', 'w') as json_file:
                        json.dump(dcc_min, json_file, indent=4)


                else:
                    print("DCC validation failed or issuer signature is invalid.")
                
            except FileNotFoundError:
                print(f"File '{json_name}' not found. Please try again.")
            except json.JSONDecodeError:
                print("Failed to parse JSON. Ensure the file is a valid DCC JSON.")
            except Exception as e:
                print(f"Error during minimal DCC generation: {e}")
          
        elif choice == "2":
            print("Exiting the program. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice. Please choose a valid option.")

if __name__ == "__main__":
    main_menu()
