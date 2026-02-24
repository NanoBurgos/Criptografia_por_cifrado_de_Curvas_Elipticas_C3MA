from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
# ============================
# 1. Generación de claves
# ============================
# Alice genera su clave privada
alice_private_key = x25519.X25519PrivateKey.generate()
alice_public_key = alice_private_key.public_key()
# Bob genera su clave privada
bob_private_key = x25519.X25519PrivateKey.generate()
bob_public_key = bob_private_key.public_key()
# ============================
# 2. Cálculo del secreto compartido
# ============================
alice_shared_secret = alice_private_key.exchange(bob_public_key)
bob_shared_secret = bob_private_key.exchange(alice_public_key)
print("¿Coinciden los secretos?:",
alice_shared_secret == bob_shared_secret)
# ============================
# 3. Derivación de clave simétrica (recomendado)
# ============================
derived_key = HKDF(
    algorithm=hashes.SHA256(),
length=32,
salt=None,
info=b'handshake data',
).derive(alice_shared_secret)
print("Clave derivada (hex):", derived_key.hex())