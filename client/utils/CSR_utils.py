import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_FILE_PATH = os.path.join("client_path", "certificates")

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

def generate_csr(username: str, passphrase: str):
    """
    Generates a CSR for a given username.
    Encrypts the private key with the given passphrase.
    Returns (csr_pem, private_key_pem)
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Build CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyApp"),
        ])
    ).sign(private_key, hashes.SHA256())

    # Serialize CSR
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # Serialize private key with passphrase protection
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )

    return csr_pem, private_key_pem