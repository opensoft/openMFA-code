"""Ephemeral qualification credentials; never enrolls an external identity."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate(directory):
    root = Path(directory)
    root.mkdir(mode=0o700)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "run-owned-reference-ca")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256()))
    fingerprints = {}
    for role in ("custody", "agent", "verifier", "unknown"):
        folder = root / role
        folder.mkdir(mode=0o755)
        (folder / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
                   .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(minutes=20))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if role == "custody"
                                                       else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True))
        if role == "custody":
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("custody")]), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        (folder / "certificate.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        # Only this role directory is mounted. The trusted driver's private
        # parent stays mode 0700; no signing key enters the build context.
        (folder / "client.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        for path in folder.iterdir():
            path.chmod(0o644)
        fingerprints[role] = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return fingerprints
