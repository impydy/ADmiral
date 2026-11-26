## ADmiral 0.7.0

### Újdonságok
- **Csomagkönyvtár:** a telepítőket és frissítéseket egy helyen tárolod. Új csomagnál csak név és azonosító kell. A feltöltés állapotát az állapotsor mutatja.
- **Windows-frissítések:** a lekérdezett gépek Windows buildjeihez `.msu`/`.cab` frissítést adhatsz hozzá. Ezek buildenként csoportosítva jelennek meg. Az ADmiral a Windows Update Catalogban ellenőrzi, hogy a fájl valóban a Microsofté. A telepítés távolról, DISM-mel fut, a haladás a naplóban követhető, és közben más munka is mehet.
- **Csomagok (telepítési láncok):** lépések sorozata, amely gépenként sorban fut: telepítés, másolás, törlés, lekérdezés, újraindítás, leállítás, Wake on LAN, PowerShell, cmd, várakozás és üzenetküldés. Lenyitva látod a lépéseket.
- **Üzenet küldése:** az Eszközök között. Üzenetet küldhetsz a bejelentkezett felhasználóknak, a címzetteket gépenként, gyűjteményenként vagy OU-nként választod ki.
- **Gyűjtemények és jelentések:** egy gombbal hozhatsz létre dinamikus vagy statikus gyűjteményt. Az exportálás helyett jelentésszerkesztő van: oszlopok, szűrők, és a jelentésből statikus gyűjtemény is készülhet. Minden táblázat rendezhető.
- **Leltár:** a leltár mostantól a helyi felhasználókat, a helyi csoportokat, a felhasználói profilokat és a monitorokat is mutatja. Megjelenik a BitLocker állapota is. A helyreállítási kulcs titkosítva tárolódik, és csak az AD-jelszó újbóli megadása után látható.
- **Belépési előzmények:** a lekérdezéskor bejelentkezett felhasználó is bekerül (gépenként naponta egyszer). A megőrzési idő beállítható, alapból 2 hónap.
- **Sérülékenységek:** a régi és verzió nélküli CVE-k, valamint a hálózaton nem futó buildek alapból rejtve vannak.
- **Szinkron tűzfalszabály:** ha csak az egyik irányban működik a szinkron, a Beállításokban egy kattintással létrehozhatod a szükséges tűzfalszabályt, vagy letöltheted a szkriptet.
- **Felület:** az Áttekintés külön menüpont lett. A bal oldali sávból lekerült a Discord, a Jelentések és a Szkennerek.

### Biztonság
- A Windows-frissítéseket csak érvényes Microsoft-aláírással telepíti.
- A CSV exportokban a táblázatkezelő képletek nem futnak le.
- Gyorsabb és biztonságosabb útvonal-ellenőrzés.

### Frissítés
Töltsd le az `ADmiral-Setup-0.7.0.exe` fájlt, és futtasd a régi verzió fölött. A beállítások és az adatok megmaradnak.

---

## ADmiral 0.7.0

### New
- **Package library:** installers and updates in one place. A new package only needs a name and an ID. The status bar shows the upload progress.
- **Windows updates:** add `.msu`/`.cab` updates for the Windows builds found on your network, grouped by build. ADmiral checks in the Windows Update Catalog that the file really is Microsoft's. Installation runs remotely with DISM, its progress shows in the log, and other work can go on meanwhile.
- **Packages (installation chains):** steps that run in order on each computer: install, copy, delete, scan, restart, shut down, Wake on LAN, PowerShell, cmd, wait and send message. Open a chain to see its steps.
- **Send message:** under Tools. Send a message to the logged-on users; pick the targets by computer, collection or OU.
- **Collections and reports:** one button creates a dynamic or static collection. Export is replaced by a report editor: columns, filters, and a static collection made from the report. Every table can be sorted.
- **Inventory:** the inventory now also shows local users, local groups, user profiles and monitors, plus the BitLocker state. The recovery key is stored encrypted and shown only after you enter the AD password again.
- **Logon history:** the user logged on during a scan is added too (once a day per computer). How long the history is kept can be set; the default is 2 months.
- **Vulnerabilities:** old CVEs, CVEs without a version and builds not running on your network are hidden by default.
- **Sync firewall rule:** if sync works in one direction only, Settings can add the needed firewall rule with one click, or give you the script.
- **Interface:** Overview has its own menu item. Discord, Reports and Scanners are gone from the left bar.

### Security
- Windows updates are installed only with a valid Microsoft signature.
- Spreadsheet formulas in CSV exports no longer run.
- Faster and safer path checking.

### Updating
Download `ADmiral-Setup-0.7.0.exe` and run it over the old version. Your settings and data are kept.

Check `SHA256SUMS.txt` if you want to verify the download.
