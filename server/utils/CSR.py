from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta, timezone

def sign_csr(csr_data : bytes, root_key, root_cert, validity_days: int = 365) -> bytes:
    """
    Signs a CSR using the root CA key and certificate.

    :param csr_data: CSR in PEM format or in Bytes
    :param root_key: Root CA private key
    :param root_cert: Root CA certificate
    :param validity_days: How long the signed certificate is valid
    :return: Signed certificate in PEM bytes
    :raises ValueError: If CSR is invalid
    """

    csr = x509.load_pem_x509_csr(csr_data)

    client_cert = x509.CertificateBuilder()\
        .subject_name(csr.subject)\
        .issuer_name(root_cert.subject)\
        .public_key(csr.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.now(timezone.utc))\
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))\
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )\
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False
        )\
        .sign(private_key=root_key, algorithm=hashes.SHA256())

    return client_cert.public_bytes(serialization.Encoding.PEM)