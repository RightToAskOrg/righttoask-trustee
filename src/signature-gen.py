import base64
import secrets
from nacl.signing import SigningKey

secret = secrets.token_bytes(32)
secret_enc = base64.b64encode(secret).decode("utf-8")
pubkey_enc = base64.b64encode(SigningKey(secret).verify_key.encode()).decode("utf-8")

print(f'"public_key": "{pubkey_enc}",\n"private_key": "{secret_enc}"')
