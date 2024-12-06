from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.x509 import NameOID
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes

password=b"123456"
private_key_hex = 0x869176bf92b63061b59a26eff6370d26125720844987a60537dee3bff08740fb
# Decode the hex key
#private_key_bytes = bytes.fromhex(private_key_hex)

# Load the private key
private_key = ec.derive_private_key(
    private_key_hex,
    ec.SECP256R1(),
    default_backend()
)

# Generate a self-signed certificate (optional)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"issuer.trace4eu.eu"),
])

certificate = x509.CertificateBuilder()\
    .subject_name(subject)\
    .issuer_name(issuer)\
    .public_key(private_key.public_key())\
    .serial_number(x509.random_serial_number())\
    .not_valid_before(datetime.utcnow())\
    .not_valid_after(datetime.utcnow() + timedelta(days=365))\
    .sign(private_key, hashes.SHA256())

# Convert the private key and certificate to PKCS#12
pkcs12_data = serialize_key_and_certificates(
    name=b"ecdsa_key_2",
    key=private_key,
    cert=certificate,
    cas=None,  # No additional certificates in the chain
    encryption_algorithm=BestAvailableEncryption(password)
)

# Save the PKCS#12 bundle to a file
with open("keys/did_ebsi.p12", "wb") as pkcs12_file:
    pkcs12_file.write(pkcs12_data)

print("PKCS#12 bundle saved as output.p12")