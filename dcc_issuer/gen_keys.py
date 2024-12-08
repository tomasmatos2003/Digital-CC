from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# Function to generate the RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Save private key to PEM format
    with open("private_key.pem", "wb") as private_pem_file:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_pem_file.write(private_pem)
        print("Private key saved to private_key.pem")

    # Save public key to PEM format
    with open("public_key.pem", "wb") as public_pem_file:
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_pem_file.write(public_pem)
        print("Public key saved to public_key.pem")

    return private_key, public_key


# Function to generate a self-signed certificate
def generate_self_signed_certificate(private_key, public_key):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mycompany.com"),
    ])

    issuer = subject  # For self-signed certificates, issuer is the same as subject

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Save certificate to a PEM file
    with open("self_signed_certificate.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print("Self-signed certificate saved to self_signed_certificate.pem")


# Function to sign data (for DCC)
def sign_data(private_key, data):
    signature = private_key.sign(
        data.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


# Main function to execute the generation and save the keys and certificate
def main():
    # Step 1: Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()

    # Step 2: Generate and save self-signed certificate
    generate_self_signed_certificate(private_key, public_key)

if __name__ == "__main__":
    main()
