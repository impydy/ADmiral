## ADmiral 0.6.1 – javítások

Ez a kiadás az első visszajelzések alapján javít öt hibát.

### Javítások
- **Licenc a telepítőben:** a régi EULA helyett a GPL-3.0 tájékoztató jelenik meg (magyarul és angolul), elfogadás nélkül. A teljes licenc `LICENSE.txt` néven a programmappába kerül.
- **Rendszergazdai indítás:** az ADmiral mindig rendszergazdai joggal fut. Ha sima felhasználóként indítod, a Windows rákérdez (UAC). Így megszűnik a `C:\ProgramData\ADmiral` mappa elérési hibája. Az „ADmiral retry” szolgáltatást ez nem érinti.
- **Címsor:** a címsor követi a program témáját (világos / sötét / Windows-beállítás), és témaváltáskor azonnal vált. Windows 11-en a színe is egyezik az eszköztáréval.
- **Felhasználók oldal:** nem jelenik meg többé a „cannot set properties of null” hiba. A felhasználók száma az alsó állapotsorban látszik.
- **Proxy (407-es hiba):**
  - A proxy felhasználóneve `felhasználó@tartomány` és `TARTOMÁNY\felhasználó` alakban is működik, Basic, Digest, NTLM és Kerberos hitelesítéssel.
  - A megadott fiókot a program akkor is használja, ha a proxy címe üres, és a Windows proxybeállítása érvényes.
  - Új **Proxy teszt** gomb a Beállítások → Proxy alatt. Megmutatja, melyik proxyn megy a forgalom, milyen bejelentkezést kér, és mit küld neki az ADmiral.
  - A 407-es hibaüzenet most konkrétan leírja a teendőt.

### Frissítés
Töltsd le az `ADmiral-Setup-0.6.1.exe` fájlt, és futtasd a régi verzió fölött. A beállítások és az adatok megmaradnak.

---

## ADmiral 0.6.1 – fixes

This release fixes five problems reported after the first release.

### Fixes
- **License in the installer:** the old EULA is replaced by the GPL-3.0 notice (Hungarian and English), with nothing to accept. The full license is installed as `LICENSE.txt` in the program folder.
- **Administrator start:** ADmiral always runs with administrator rights. Started as a normal user, Windows asks for them (UAC). This fixes the access error on the `C:\ProgramData\ADmiral` folder. The "ADmiral retry" service is not affected.
- **Title bar:** the title bar follows the program's theme (light / dark / Windows setting) and switches right away when the theme changes. On Windows 11 its colour matches the toolbar too.
- **Users page:** the "cannot set properties of null" error is gone. The user count shows in the status bar.
- **Proxy (error 407):**
  - The proxy user name works as `user@domain` and as `DOMAIN\user`, with Basic, Digest, NTLM and Kerberos authentication.
  - The account is also used when the proxy address is left empty and Windows' proxy setting applies.
  - New **Test proxy** button under Settings → Proxy. It shows which proxy the traffic goes through, what login it asks for and what ADmiral sends it.
  - The 407 error message now says exactly what to do.

### Updating
Download `ADmiral-Setup-0.6.1.exe` and run it over the old version. Your settings and data are kept.

Check `SHA256SUMS.txt` if you want to verify the download.
