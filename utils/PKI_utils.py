import os
from dotenv import load_dotenv
load_dotenv()

from datetime import datetime, timedelta, timezone
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

CERT_DIR = os.path.join('server', 'certificates')
os.makedirs(CERT_DIR, exist_ok=True)

ROOT_KEY_PATH = os.path.join(CERT_DIR, "root_key.pem")
ROOT_CERT_PATH = os.path.join(CERT_DIR, "root_cert.pem")
SERVER_KEY_PATH = os.path.join(CERT_DIR, "server_key.pem")
SERVER_CERT_PATH = os.path.join(CERT_DIR, "server_cert.pem")

ROOT_KEY_PASSPHRASE = os.getenv("ROOT_KEY_PASSPHRASE").encode()
SERVER_KEY_PASSPHRASE = os.getenv("Server_KEY_PASSPHRASE").encode()


# ---------------- LOAD PRIVATE KEY ----------------
def load_private_key(path, password):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


# ---------------- ROOT CA ----------------
def generate_root_ca():
    if os.path.exists(ROOT_KEY_PATH) and os.path.exists(ROOT_CERT_PATH):
        # Load existing
        root_key = load_private_key(ROOT_KEY_PATH, ROOT_KEY_PASSPHRASE)
        with open(ROOT_CERT_PATH, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
        return root_key, root_cert

    now = datetime.now(timezone.utc)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])

    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now)\
        .not_valid_after(now + timedelta(days=3650))\
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )\
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                key_encipherment=False,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=True
            ),
            critical=True
        )\
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )\
        .add_extension(ski, critical=False)\
        .sign(private_key, hashes.SHA256())

    with open(ROOT_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.BestAvailableEncryption(ROOT_KEY_PASSPHRASE)
        ))
    with open(ROOT_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return private_key, cert


# ---------------- SERVER CERTIFICATE SIGNING ----------------
def generate_server_certificate(root_key, root_cert, common_name="localhost"):
    if os.path.exists(SERVER_KEY_PATH) and os.path.exists(SERVER_CERT_PATH):
        # Load existing
        server_key = load_private_key(SERVER_KEY_PATH, SERVER_KEY_PASSPHRASE)
        with open(SERVER_CERT_PATH, "rb") as f:
            server_cert = x509.load_pem_x509_certificate(f.read())
        return server_key, server_cert

    now = datetime.now(timezone.utc)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key())
    
    san = x509.SubjectAlternativeName([
        x509.DNSName(common_name),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
    ])
    
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(root_cert.subject)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now)\
        .not_valid_after(now + timedelta(days=365))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False
            ),
            critical=True
        )\
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)\
        .add_extension(san, critical=False)\
        .add_extension(ski, critical=False)\
        .add_extension(aki, critical=False)\
        .sign(root_key, hashes.SHA256())
    
    with open(SERVER_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.BestAvailableEncryption(SERVER_KEY_PASSPHRASE)
        ))
    
    with open(SERVER_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    return private_key, cert


# ---------------- SIGN FILES ----------------
def sign_bytes(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_bytes(public_key, data: bytes, signature: bytes) -> None:
    public_key.verify(
        signature,
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )