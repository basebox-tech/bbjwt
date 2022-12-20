"""
Python script that creates JWTs and signs them with a key provided on the command line.

The generated JWTs are for testing bbjwt and contain a static set of claims. Two JWTs are
created: one that is expired and another that expires around the year 3022.

This script is necessary since jwt.io cannot create OKP JWTs (signed with Ed25519).

Usage:

* Create a virtual environment for Python3
* Activate it
* Install dependencies (pip install -r requirements.txt)
* Run it (python3 jwt_create.py /path/to/jwk.json)

Author: markus.thielen@basebox.tech
"""

from jwcrypto import jwk, jwt
import json
import sys


# We expect a JSON JWK containing public and private key as the only argument.
if len(sys.argv) < 2:
    print("\nGive me a JWK file path as the only argument. Thanks!")
    sys.exit(1)

key = None
json_key = None

try:
    f = open(sys.argv[1], "r")
    json_key = json.load(f)
    f.close()
    key = jwk.JWK(**json_key)
except Exception as e:
    print(f'Failed to read/parse JWK "{sys.argv[1]}": {str(e)}')
    sys.exit(1)

expired_time = 1670265186

payload = {
  "exp": 33206263475,
  "iat": 1670265186,
  "auth_time": 1670265185,
  "jti": "c2121c79-9417-437c-9325-61327f01e10b",
  "iss": "https://kc.basebox.health/realms/testing",
  "aud": "test-1",
  "sub": "13529346-91b6-4268-aae1-f5ad8f44cf4d",
  "typ": "ID",
  "azp": "test-1",
  "nonce": "UZ1BSZFvy7jKkj1o9p3r7w",
  "session_state": "a8e97763-4723-4d1d-a343-3c13d3a2386f",
  "at_hash": "J1NZLZGtyg0zOzv_UuebPA",
  "acr": "1",
  "sid": "a8e97763-4723-4d1d-a343-3c13d3a2386f",
  "email_verified": True,
  "address": {},
  "Patient": "crud",
  "groups": [
    "receptionist",
    "therapist"
  ],
  "Doctor": "cr",
  "preferred_username": "tester",
  "given_name": "Max",
  "upn": "tester",
  "claim5": "<----------<More Text>---------->",
  "claim4": True,
  "name": "Max Mustermann",
  "claim3": 100,
  "claim2": 3,
  "claim1": "I have added some text here",
  "family_name": "Mustermann",
  "email": "test@basebox.health"
}

# Create the header, using "alg" and "kty" from the JWK
jose_header = {
    "typ": "JWT",
    "kid": "key-1",
    "alg": json_key["alg"],
    "kty": json_key["kty"],
}
curve = json_key.get("crv", "None")
if curve:
    jose_header["crv"] = curve

token = jwt.JWT(
    header=jose_header,
    claims=payload,
)

# Sign
token.make_signed_token(key)

# print valid JWT
print("\n\nValid JWT:")
print(token.serialize())

# create expired JWT
payload["expired"] = expired_time
token = jwt.JWT(
    header=jose_header,
    claims=payload,
)

# Sign
token.make_signed_token(key)

# print expired JWT
print("\n\nExpired JWT:")
print(token.serialize())
print("\n")
