from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

clave_privada = ec.generate_private_key(ec.SECP256R1())
clave_publica = clave_privada.public_key()

with open("clave_privada.pem", "wb") as f:
    f.write(clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("clave_publica.pem", "wb") as f:
    f.write(clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Claves ECC generadas: clave_privada.pem, clave_publica.pem")
