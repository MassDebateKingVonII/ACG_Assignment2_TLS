import os

from dotenv import load_dotenv
load_dotenv()

from utils.cert_utils import load_certificate, load_private_key

from datetime import datetime, timedelta, timezone
import ipaddress
from cryptography import x509
from cryptography.x509 import KeyUsage
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

CERT_DIR = os.path.join('server', 'certificates')
os.makedirs(CERT_DIR, exist_ok=True)

ROOT_KEY_PATH = os.path.join(CERT_DIR, "root_key.pem")
ROOT_CERT_PATH = os.path.join(CERT_DIR, "root_cert.pem")
SERVER_KEY_PATH = os.path.join(CERT_DIR, "server_key.pem")
SERVER_CERT_PATH = os.path.join(CERT_DIR, "server_cert.pem")
FILE_KEY_PATH = os.path.join(CERT_DIR, "file_sign_key.pem")
FILE_CERT_PATH = os.path.join(CERT_DIR, "file_sign_cert.pem")

ROOT_KEY_PASSPHRASE = os.getenv("ROOT_KEY_PASSPHRASE").encode()
SERVER_KEY_PASSPHRASE = os.getenv("SERVER_KEY_PASSPHRASE").encode()


# ---------------- HELPERS ----------------
def load_or_generate_cert(key_path, cert_path, subject_name, issuer_key=None, issuer_cert=None,
                          is_ca=False, eku=None, san=None, validity_days=365, key_passphrase=None):
    # Load existing
    if os.path.exists(key_path) and os.path.exists(cert_path):
        key = load_private_key(key_path, key_passphrase)
        cert = load_certificate(cert_path)
        return key, cert

    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    issuer = issuer_cert.subject if issuer_cert else subject

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )

    # Authority Key Identifier if issued by a CA
    if issuer_key and issuer_cert:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False
        )

    # Add KeyUsage based on CA vs end-entity
    if is_ca:
        builder = builder.add_extension(
            KeyUsage(
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
        )
    else:
        # End-entity cert (server)
        builder = builder.add_extension(
            KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=False
            ),
            critical=True
        )

    # Add EKU if provided
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)

    # Add SAN if provided
    if san:
        builder = builder.add_extension(san, critical=False)

    # Sign certificate
    cert = builder.sign(private_key=issuer_key or key, algorithm=hashes.SHA256())

    # Save private key
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.BestAvailableEncryption(key_passphrase) if key_passphrase else serialization.NoEncryption()
        ))

    # Save certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key, cert

# ---------------- GENERATE ROOT CA ----------------
def generate_root_ca():
    return load_or_generate_cert(
        ROOT_KEY_PATH, ROOT_CERT_PATH, "Root CA",
        is_ca=True,
        key_passphrase=ROOT_KEY_PASSPHRASE,
        validity_days=3650
    )


# ---------------- GENERATE SERVER CERT ----------------
def generate_server_certificate(root_key, root_cert, common_name="localhost", ip_address="127.0.0.1"):
    san = x509.SubjectAlternativeName([
        x509.DNSName(common_name),
        x509.IPAddress(ipaddress.IPv4Address(ip_address))
    ])
    return load_or_generate_cert(
        SERVER_KEY_PATH, SERVER_CERT_PATH, common_name,
        issuer_key=root_key,
        issuer_cert=root_cert,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        san=san,
        validity_days=90,
        key_passphrase=SERVER_KEY_PASSPHRASE
    )


# ---------------- GENERATE FILE SIGNING KEY ----------------
def generate_file_signing_key(root_key, root_cert):
    return load_or_generate_cert(
        FILE_KEY_PATH, FILE_CERT_PATH, "File Signing Key",
        issuer_key=root_key,
        issuer_cert=root_cert,
        eku=[ExtendedKeyUsageOID.CODE_SIGNING],
        validity_days=365,
        key_passphrase=SERVER_KEY_PASSPHRASE
    )