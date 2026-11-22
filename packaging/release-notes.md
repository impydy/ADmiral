## ADmiral 0.6.0 – az első nyilvános kiadás 🎉

Szia! Ez az ADmiral első kiadása itt a GitHubon. Egy kis Windows-program, amivel átláthatod az Active Directory-s gépeidet: mi van rajtuk, ki lép be, mi hiányzik róluk, és telepítőket is ki tudsz rájuk küldeni – ügynök nélkül.

### Mi van benne
- Gépek AD-ból, online/offline állapot, teljes leltár (hardver, szoftver, szolgáltatások, frissítések, belépések)
- Statikus és szabály alapú (dinamikus) gyűjtemények
- Szoftverek és ismert sérülékenységek (NVD + CISA KEV), Windows-frissítések állapota
- Telepítések a csomagtárból, eredményekkel és egykattintásos újrapróbálással
- Nyomtatók (SNMP), felhasználók, offline gépek fájlos leltára, szinkron több ADmiral között
- Magyar és angol felület

### Telepítés
Töltsd le az `ADmiral-Setup-0.6.0.exe` fájlt, futtasd, aztán a Beállításokban add meg az AD-t. Nem kell hozzá .NET.

---

## ADmiral 0.6.0 – first public release 🎉

Hi! This is the first release of ADmiral on GitHub. It's a small Windows tool for keeping track of the computers in your Active Directory: what's on them, who logs on, what they're missing, and you can push installers to them too – no agent needed.

### What's in it
- Computers from AD, online/offline state, full inventory (hardware, software, services, updates, logons)
- Static and rule-based (dynamic) collections
- Software and known vulnerabilities (NVD + CISA KEV), Windows update status
- Deployments from the package library, with results and one-click retries
- Printers (SNMP), users, file-based inventory for offline machines, sync between ADmiral instances
- Hungarian and English UI

### Installing
Download `ADmiral-Setup-0.6.0.exe`, run it, then set up your AD in Settings. No .NET install needed.

Check `SHA256SUMS.txt` if you want to verify the download.
