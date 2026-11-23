## ADmiral 0.6.2 – javítások

### Javítások
- **Belépéskövetés:** a szkript nem hagy többé `.tmp` fájlokat a mappában. Közvetlenül a `.log` fájlt írja, ezért a gépeknek elég a „Fájlok létrehozása” jog. A régi szkript ottmaradt `.tmp` fájljait az ADmiral beolvassa és törli. Mentsd el újra az `ADmiral-Logins.ps1`-et a Beállításokból.
- **Szinkron:** ha a másik ADmiral nem tudta lekérdezni a gépet, a szinkron nem törli többé a meglévő leltáradatot. A gépet lekérdező oldal adata átmegy a másikhoz, a belépési előzmények összeadódnak.
- **Gépnevek:** az ékezetes nevű (pl. `KÖNYVELÉS-PC`) és a kötőjelre végződő gépek is lekérdezhetők.
- **Naplócsomag:** a „Mappa megnyitása” helyett **Mentés ZIP-ként…** gomb van. A mappa jogosultság hiánya miatt nem nyílt meg, a ZIP-et viszont bárhová elmentheted, és feltöltheted a hibajegyhez.
- **Anonimizálás:** a naplócsomag nem cseréli többé a programkód szavait (pl. `Task`) domainnévre, így a hibajelentés olvasható marad.
- **Hotfixek:** a telepített frissítések dátuma magyar Windowson is megjelenik.
- **Hibanapló:** az elérhetetlen gépek miatti „Unobserved task exception” hibák eltűntek.
- **Szinkron teszt:** üres címmel a gomb szól, hogy előbb add meg a címet. Időtúllépésnél érthető üzenetet kapsz.
- **Proxy:** új kapcsoló a Beállítások → Proxy alatt. Bekapcsolva a fiókot az automatikusan (WPAD) vagy http-n letöltött PAC-fájl proxyja is megkapja. Akkor kell, ha a hálózatban csak így érhető el a PAC-fájl.

### Frissítés
Töltsd le az `ADmiral-Setup-0.6.2.exe` fájlt, és futtasd a régi verzió fölött. A beállítások és az adatok megmaradnak.

---

## ADmiral 0.6.2 – fixes

### Fixes
- **Login tracking:** the script no longer leaves `.tmp` files in the folder. It writes the `.log` file directly, so computers only need the "Create files" right. Leftover `.tmp` files of the old script are read and deleted. Save `ADmiral-Logins.ps1` again from Settings.
- **Sync:** when the other ADmiral could not collect a computer, sync no longer deletes the inventory you already have. The side that collected it sends it over, and logon histories are merged.
- **Computer names:** computers with accented names (e.g. `KÖNYVELÉS-PC`) or names ending in a hyphen can be collected now.
- **Log package:** "Open folder" is replaced by **Save as ZIP…**. The folder could not be opened because of its permissions; the ZIP can be saved anywhere and attached to an issue.
- **Anonymization:** the log package no longer turns code words (like `Task`) into domain names, so the error report stays readable.
- **Hotfixes:** the install date of updates shows on Hungarian Windows too.
- **Error log:** the "Unobserved task exception" errors caused by unreachable computers are gone.
- **Sync test:** with an empty address the button tells you to enter one first. A timeout now gives a clear message.
- **Proxy:** new switch under Settings → Proxy. When it is on, the account is also given to a proxy named by a PAC file found automatically (WPAD) or downloaded over http. Use it only if your network offers the PAC file only that way.

### Updating
Download `ADmiral-Setup-0.6.2.exe` and run it over the old version. Your settings and data are kept.

Check `SHA256SUMS.txt` if you want to verify the download.
