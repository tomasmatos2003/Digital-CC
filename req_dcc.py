from PyKCS11 import PyKCS11, Mechanism, CKM_SHA1_RSA_PKCS
from PyKCS11.LowLevel import *
import sys
import socket
import json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der.decoder import decode
from pyasn1.type.univ import Sequence
import hashlib
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from datetime import datetime, timezone

lib = '/usr/local/lib/libpteidpkcs11.so' 
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)

gen_dcc_host = '127.0.0.1'  
gen_dcc_port = 65432       


def create_dcc(cc_data):
    """
    Formats the retrieved Citizen Card data into a Digital Commitment Credential (DCC).
    """
    if not cc_data:
        print("No Citizen Card data provided.")
        return None

    # Placeholder for the commitment mask derivation (use a secure method for production)
    def derive_mask(password, attribute_name):
        return hashlib.sha256(f"{password}{attribute_name}".encode()).hexdigest()

    # Placeholder for creating a commitment value
    def create_commitment(attribute_name, attribute_value, mask):
        combined = f"{attribute_name}{attribute_value}{mask}".encode()
        return hashlib.sha256(combined).hexdigest()

    pseudo_random_password = "securepassword"

    # Extract attributes from cc_data
    attributes = cc_data["identity"]
    commitments = []

    # Generate commitment values for attributes
    for label, value in attributes.items():
        if value is None:
            continue
        mask = derive_mask(pseudo_random_password, label)
    
        commitment = create_commitment(label, value, mask)
        commitments.append({
            "label":label,
            "value": value,
            "commitment": commitment
        })


    not_before_mask = derive_mask(pseudo_random_password, "val_not_before")
    commitments.append({
        "label":"val_not_before",
        "value": cc_data["validity"]["not_before"],
        "commitment": create_commitment("val_not_before", cc_data["validity"]["not_before"], not_before_mask)
    })

    not_after_mask = derive_mask(pseudo_random_password, "val_not_after")
    commitments.append({
        "label":"val_not_after",
        "value": cc_data["validity"]["not_after"],
        "commitment": create_commitment("val_not_after", cc_data["validity"]["not_after"], not_after_mask)
    })

    # Generate the DCC structure
    dcc = {
        "identity_attributes": commitments,
        "digest_function": "SHA-256",
        "public_key": {
            "value": cc_data["public_key"]["algorithm"],
            "key_size": cc_data["public_key"]["key_size"]
        }
    }

    # Return the DCC with the signature
    return dcc

def get_birth_date_from_extension(extension):
    try:
        decoded_value, _ = decode(extension)
        for seq in decoded_value:
            if isinstance(seq, Sequence):
                oid = str(seq[0])  # Extract the OID
                if oid == "1.3.6.1.5.5.7.9.1":  # Birth Date OID
                    # Extract the associated value
                    birth_date_raw = seq[1][0]  # Get the SetOf value
                    birth_date_str = birth_date_raw.asOctets().decode()  # Convert to string
                    
                    # Convert the string to a datetime object
                    birth_date = datetime.strptime(birth_date_str, "%Y%m%d%H%M%SZ")
                    
                    # Set timezone to UTC (as 'Z' in the string indicates UTC)
                    birth_date = birth_date.replace(tzinfo=timezone.utc)
                    
                    return birth_date
        return None 
    except Exception as e:
        print(f"Error decoding subjectDirectoryAttributes: {e}")
        return None

def get_portuguese_cc_data():
    
    slots = pkcs11.getSlotList(tokenPresent=True)
    
    for slot in slots:
        token_info = pkcs11.getTokenInfo(slot)
        if "CARTAO DE CIDADAO" in token_info.label:
            print("Portuguese Citizen Card detected.")

            session = pkcs11.openSession(slot)
            try:
                # Look for certificate objects
                objects = session.findObjects([
                    (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_CERTIFICATE)
                ])

                for obj in objects:
                    attributes = session.getAttributeValue(obj, [
                        PyKCS11.LowLevel.CKA_LABEL,
                        PyKCS11.LowLevel.CKA_VALUE
                    ])
                    
                    label = attributes[0].decode() if isinstance(attributes[0], bytes) else attributes[0]
                    cert_value = attributes[1]

                    if "CITIZEN AUTHENTICATION CERTIFICATE" in label:

                        if isinstance(cert_value, tuple):
                            cert_value = bytes(cert_value)  # Convert tuple of ints to bytes

                        if isinstance(cert_value, bytes):
                  
                            # Parse the certificate
                            cert = x509.load_der_x509_certificate(cert_value)
                            subject = cert.subject

                            # Extract details
                            full_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                            id_number = subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
                            
                            # Additional data (may require custom OIDs for NIF, NSS, Utent, Birth Date)
                            country = (
                                subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
                                if subject.get_attributes_for_oid(NameOID.COUNTRY_NAME) else None
                            )
                            organization = (
                                subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
                                if subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else None
                            )

                            public_key = cert.public_key()
                          
                            for ex in cert.extensions:
                                oid = ex.oid.dotted_string
                                if oid == "2.5.29.9":  # subjectDirectoryAttributes OID
                                    birth_date = get_birth_date_from_extension(ex.value.value)
                                
                              
                            return {
                                "identity": {
                                    "full_name": full_name,
                                    "id_number": id_number,
                                    "country": country,
                                    "organization": organization,  
                                    "birth_date" : birth_date 
                                },
                                "validity": {
                                    "not_before": cert.not_valid_before_utc,
                                    "not_after": cert.not_valid_after_utc,
                                }, 
                                "public_key": {
                                    "algorithm": public_key.public_bytes(
                                        encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                                    ).decode(),
                                    "key_size": public_key.key_size,
                                }
                            }
                        else:
                            print("Certificate value is not in a valid byte format.")
                            return None

            except Exception as e:
                print(f"Error retrieving data: {e}")
            finally:
                session.closeSession()

    print("No valid data found on the Citizen Card.")
    return None

def send_receive_dictionary(dictionary):

    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((gen_dcc_host, gen_dcc_port))
            message = json.dumps(dictionary, default=str)
            client_socket.sendall(message.encode('utf-8'))
            # print(f"Sent data: {dictionary}")
            print("Sent pré-dcc sucessfully")

            buffer = b""
            while True:
                chunk = client_socket.recv(1024)  # Read in chunks
                if not chunk:  # Stop if no more data
                    break
                buffer += chunk

            # Decode and process the full response
            response_dict = json.loads(buffer.decode('utf-8'))
            # print(f"Server response: {response_dict}")
            print("Received final dcc sucessfully")

            return response_dict

    except Exception as e:
        print(f"Error during authentication: {e}")

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
        print(serialized_only_commitment)
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

                    with open('dcc.json', 'w') as json_file:
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
