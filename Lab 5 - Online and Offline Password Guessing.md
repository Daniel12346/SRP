# Lab 5 - Online and Offline Password Guessing

 Alati koji nam trebaju za ovu vježbu su nmap, hydra i hashcat. 
 Osnovne informacije o nmap-u možemo saznati komandom whatis.
 ``whatis nmap
nmap (1)             - Network exploration tool and security / port scanner
``

## Online Password Guessing

Koristimo nmap na lokalnoj mreži: 
``` 
nmap -v 10.0.15.0/28
```
Nmap skenira dostupna računala i traži otvorene portove.
Na http://a507-server.local/ pronalazim docker container koji mi pripada. Njegov username je vrandecic_daniel, a IP adresa 10.0.15.0. Ne mogu se povezati
na svoj container pomoću ssh vrandecic_daniel@10.0.15.0 jer je potrebna lozinka koju ne znam.
Znamo da lozinka ima 4 do 6 znakova koji mogu biti od a do z (lowercase) - ukupno 26 mogućih znakova.
Postoji 26^4 mogućnosti ako ima 4 znaka, 26^5 ako ima 5 znakova ili 26^6 ako ima 6 znakova.
Ukupan password space je 26^4 + 26^5 + 26^6 što je približno 2^29. 

Pozivamo hydra s poznatim korisničkim imenom, IP adresom containera i ograničenjima lozinke.
```hydra -l vrandecic_daniel -x 4:6:a 10.0.15.0 -V -t 4 ssh```
U outputu je navedeno da je rate (brzina testiranja) 64 test/s = 2^6 test/s. Budući da je lozinka vjerojatno u prvoj polovici password spacea veličine 2^29, dovoljno je 2^28 testova.
Potrebno vrijeme da ih se izvrši uz navedeni rate je T = 2^28/2^6 = 2^22 min, što je približno 8 godina. To vrijeme je predugo pa koristimo već gotov dictionary
koji
skidamo sa servera: ```wget -r -nH -np --reject "index.html*" http://a507-server.local:8080/dictionary/g5/```.
Sada pozivamo hydra s dobivenim dictionaryjem: ```hydra -l vrandecic_daniel -P dictionary/g5/dictionary_online.txt 10.0.15.0 -V -t 4 ssh```.

```
[22][ssh] host: 10.0.15.0   login: vrandecic_daniel   password: byllyt
1 of 1 target successfully completed, 1 valid password found
```

Konačno je pronađena lozinka za moj container, byllyt, i sada se mogu prijaviti u container.

## Offline Password Guessing

U /etc/shadow su hashevi lozinki. Željeni hash spremamo u hash.txt. Pokušamo pronaći lozinku pomoću 
```hashcat --force -m 1800 -a 3 hash.txt ?l?l?l?l?l?l --status --status-timer 10```, ali vidimo da bi na ovaj način trebalo bi previše vremena, pa koristimo
lokalni dictionary. 
```hashcat --force -m 1800 -a 0 hash.txt dictionary/g5/dictionary_offline.txt --status --status-timer 10```.
Nakon nekog vremena hashcat pronalazi traženu lozinku.
