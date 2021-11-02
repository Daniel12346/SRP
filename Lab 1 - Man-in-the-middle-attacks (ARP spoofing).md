# Lab 1 - Man-in-the-middle-attacks (ARP spoofing)

Na ovoj vježbi izveli smo man in the middle napad u virtualiziranoj mreži koju čine 3 Docker računala: evil-station (IP adresa 172.20.04), station 1 (IP adresa 172.20.04) i station 2 (IP adresa 172.20.04). Obavljamo **pasivni napad,** tj. evil-station, koji predstavlja napadača, prisluškuje promet između stationa 1 i 2. Komunikaciju između stationa 1 i 2 omogućava program netcat**.**

Na station 2 koristimo komandu `netcat -l -p 8000` kako bi station 2 slušao na portu 8000, tako da se station 2 ovdje ponaša kao server. Station 1 je klijent i povezuje se na station 2 s `netcat station-2 8000`. Ovime je ostvarena komunikacija među računalima, tekst napisan na jednom računalu može se vidjeti na drugom. 

Na evil-station koristimo alat arpspoof da preusmjerimo promet između stationa 1 i 2 preko evil-station komandom `arpspoof -t station-1 station-2`. Station 1 je target, a station 2 host. Evil-station se predstavlja kao station-2 tako što stvara lažne ARP odgovore. Ovako evil-station može osluškivati razmjenu paketa između stationa 1 i 2 te vidi poruke koje razmjenjuju. Ovaj man-in-the-middle napad ugrožava **povjerljivost i integritet mreže**.

U sljedećem djelu vježbe obavili smo jednostavan **DDOS** (distributed denial of service) napad.

Na evil-station komandom `echo 0>/proc/sys/net/ipv4/ip-forward` onemogućavamo IP forwarding na ovoj mreži. Onemogućeno je prosljeđivanje paketa, stationi 1 i 2 više ne mogu razmjenjivati poruke,

što znači da je ugrožena **dostupnost mreže**.

Ova vježba dokazuje ranjivost ARP protokola i koliko lako može biti narušiti sve komponente sigurnosti lokalne mreže.