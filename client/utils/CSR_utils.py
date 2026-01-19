import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CSR_FILE_PATH = os.path.join("client_path", "certificates")
KEY_FILE_PATH = os.path.join("client_path", "certificates")

def generate_csr(username: str, key_file: str = None):
    """
    Generates a CSR for a given username.
    If key_file is None, generate a new private key.
    Returns (csr_pem, private_key_pem)
    """

    # Generate private key if not provided
    if key_file:
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyApp"),
        ])
    ).sign(private_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    return csr_pem, private_key_pem