#Lab 2 - Symmetric key cryptography - a crypto challenge

Za početak stvaramo virtualno python okruženje u kojem ćemo raditi i skriptu brute_force.py.
Cilj vježbe je pronaći file čije ime je nastalo hashiranjem našeg imena te ga zatim dekriptirati. Prvo pronalazimo ime filea.
To radimo pomoću funkcije koja hashira dani input na isti način kako je hashirano ime filea. Hashiramo svoje ime i pronađemo file čije ime je jednako dobivenom hashu.

```python
def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()
```

Dakle, u mojem slučaju ime filea je

```python
filename = hash("vrandecic_daniel") + ".encrypted"
```

Ovdje unutar brute_force.py pozivamo funkciju hash i ispisujemo dobivenu vrijednost hasha:

```python
if __name__ == "__main__":
	hash_value = hash("vrandecic_daniel")
	print(hash_value)
```

Sada kad znamo ime našeg filea možemo ga preuzeti.
File koji tražimo je slika formata .png pa nam je potrebna funkcija koja uzima header nekog filea i provjerava je li taj file tog formata.

```python
def test_png(header):
    if header.startswith(b"\211PNG\r\n\032\n"):
        return True
```

Slijedi dekripcija filea brute_force pristupom tako da u beskonačnoj petlji stvaramo nove ključeve koristeći brojač iteracija
ctr i pokušavamo svakim ključem dekriptirati naš file. Jedino ako je ključ ispravan rezultat dekripcije (plaintext)je slika formata .png, koju spremamo kao BINGO.txt i time je zadatak obavljen.

```python
def brute force():
    ctr = 0;
    filename = "e131745996279e21e8529f13554a6965e1387af9dd880a07df2daf5e1f367ab7.encrypted"
    with open(filename, "rb") as file:
        ciphertext = file.read()
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)
		if not (ctr + 1) % 1000:
			print(f"[*] Keys tested: {ctr +1:,}", end = "\r")
		try:
			plaintext = Fernet(key).decrypt(ciphertext)
			header = plaintext[:32]
			if test_png(header):
				print(f"[+] KEY FOUND: {key}")
				with open("BINGO.png", "wb") as file:
					file.write(plaintext)
				break
		except Exception:
			pass

        ctr +=1
```
