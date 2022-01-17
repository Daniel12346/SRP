# Lab 3 - Message authentication and integrity

Vježba se sastoji od 2 izazova. Za preuzimanje izazova koristimo program wget.

## Izazov 1

Cilj 1. izazova je zaštiti integritet određene poruke pomoću MAC algoritma pri čemu koristimo mehanizam HMAC iz Python biblioteke cryptography.

Funkcija generate_MAC stvara MAC za danu poruku koristeći key koji je zajednički pošiljatelju i primatelju (simetrični sustav).

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature
```

Funkcija verify_MAC uspoređuje lokalni MAC s primljenim MAC-om (signature).

```python
def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True
```

Ako se promijeni sadržaj poruke, mijenja se i MAC.
Zbog toga ako promijenimo sadržaj poruke ili primljeni signature funkcija h.verify(signature) unutar verify_MAC rezultira greškom i funkcija vraća False. Tako MAC algoritam detektira obavljene promjene.

```python
if __name__ == "__main__":
    key = b"my super secret password"
    with open("message.txt", "rb") as file:
        message = file.read()

	with open("message.mac", "rb") as file:
	    signature = file.read()

    is_authentic = verify_MAC(key, signature, message)
    print(is_authentic)
```

## Izazov 2

U 2. izazovu treba odrediti pravilan vremenski redoslijed i integritet transakcija sa odgovarujućim dionicama.
Iteriramo kroz fileove i provjeravamo ispravnost MAC-a za svaki od njih. Funkcija verify_MAC je ista kao u 1. izazovu.

```python
if __name__ == "__main__":

key = "vrandecic_daniel".encode()

for ctr in range(1, 11):
    msg_filename = f"challenges\\vrandecic_daniel\mac_challenge\order_{ctr}.txt"
    sig_filename = f"challenges\\vrandecic_daniel\mac_challenge\order_{ctr}.sig"

	with open(msg_filename, "rb") as file:
		message = file.read()

	with open(sig_filename, "rb") as file:
		signature = file.read()

	is_authentic = verify_MAC(key, signature, message)

	print(f'Message {key.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

## Digital signatures using public-key cryptography

U ovom izazovu treba odrediti autentičnu sliku (između dvije ponuđene) koju je profesor potpisao svojim privatnim ključem.
Stvaramo novi file digital_signature.py.

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True

#print(load_public_key())

with open("image_2.sig", "rb") as file:
    signature = file.read()

with open("image_2.png", "rb") as file:
    image = file.read()    

is_authentic = verify_signature_rsa(signature, image)
print(is_authentic)
```
Za autentifikaciju slike koristimo javni ključ koji dobivamo pomoću load_public_key. Funkcija verify_signature_rsa provjerava digitalnog potpisa. 
Ako je potpis neispravan vraća False, inače vraća True. Za image_1.sig i image_1.png vraća False a za image_2.sig i image_2.png vraća True, dakle druga slika je autentična.
