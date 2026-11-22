using System.Globalization;
using System.Text.RegularExpressions;

namespace ADmiral.Core;

/// <summary>Server-side messages (activity log, errors) in Hungarian (default) and English.
/// The UI has its own table in wwwroot/i18n.js. <see cref="SetLanguage"/> is called whenever settings load or change.</summary>
public static partial class I18n
{
    public static readonly IReadOnlyList<string> Languages = ["hu", "en"];
    private static volatile string _lang = "hu";

    public static readonly IReadOnlyDictionary<string, (string Hu, string En)> Messages = new Dictionary<string, (string Hu, string En)>
    {
        ["log.ad_sync"] = ("{total} számítógép az AD-ben (+{added} új, -{removed} eltávolítva)", "{total} computers (+{added} new, -{removed} removed)"),
        ["log.ad_users"] = ("{total} felhasználó az AD-ből (+{added} új)", "{total} users from AD (+{added} new)"),
        ["log.sync"] = ("Szinkronizálás: {peer} ({pulled} átvéve, {pushed} elküldve)", "Sync with {peer}: {pulled} received, {pushed} sent"),
        ["sync.err_no_peer"] = ("Nincs megadva a másik ADmiral címe.", "The address of the other ADmiral is not set."),
        ["sync.err_no_key"] = ("Nincs beállítva szinkronkulcs.", "No sync key is set."),
        ["sync.err_resolve"] = ("A(z) {peer} cím nem oldható fel: {err}", "Cannot resolve {peer}: {err}"),
        ["sync.err_network"] = ("A(z) {peer} nincs az engedélyezett hálózatban ({net}).", "{peer} is not inside the allowed network ({net})."),
        ["sync.err_connect"] = ("Nem érhető el a másik ADmiral ({peer}): {err}. Fut, be van kapcsolva a szinkron, és a tűzfal engedi a portot?", "Cannot reach the other ADmiral ({peer}): {err}. Is it running with sync enabled, and does the firewall allow the port?"),
        ["sync.err_key"] = ("A másik oldal elutasította az üzenetet: a szinkronkulcs nem egyezik (vagy az órák eltérnek 5 percnél jobban).", "The other side rejected the message: the sync key differs (or the clocks differ by more than 5 minutes)."),
        ["sync.err_forbidden"] = ("A másik oldal nem fogad kapcsolatot erről a címről (más hálózat).", "The other side does not accept connections from this address (different network)."),
        ["sync.err_http"] = ("A másik oldal hibát jelzett ({code}).", "The other side reported an error ({code})."),
        ["sync.err_busy"] = ("Már fut egy szinkronizálás.", "A synchronisation is already running."),
        ["sync.err_no_common"] = ("Nincs közös szinkronizált adatkör a két oldalon.", "The two sides have no data category in common."),
        ["log.ad_scope"] = (" – innen: {ou}", " – from {ou}"),
        ["log.scan"] = ("{scanned} gép ellenőrizve ({scope}): {online} online, {offline} offline", "{scanned} scanned in {scope}: {online} online, {offline} offline"),
        ["log.collect"] = ("Leltár begyűjtve {ok} gépről, {failed} sikertelen, {skipped} kihagyva", "Inventory collected from {ok} machine(s), {failed} failed, {skipped} skipped"),
        ["err.service_admin"] = ("A szolgáltatás kezeléséhez rendszergazdai jogosultság kell: indítsa el az ADmiral-t rendszergazdaként (jobb klikk → Futtatás rendszergazdaként).", "Managing the service needs administrator rights: start ADmiral as administrator (right-click → Run as administrator)."),
        ["err.need_admin"] = ("Az ADmiral csak rendszergazdai jogosultsággal indítható. Indítsa el újra, és a Windows kérdésére (UAC) adja meg egy rendszergazda adatait, vagy: jobb klikk → Futtatás rendszergazdaként.", "ADmiral can only run with administrator rights. Start it again and answer the Windows prompt (UAC) with an administrator account, or right-click → Run as administrator."),
        ["err.service_unsupported"] = ("A szolgáltatás csak Windowson érhető el.", "The service is only available on Windows."),
        ["err.service_account"] = ("Adja meg a szolgáltatás fiókját (TARTOMÁNY\\felhasználó) és jelszavát, vagy mentse el az LDAP-fiókot a Beállításokban.", "Enter the service account (DOMAIN\\user) and its password, or save the LDAP account in Settings."),
        ["err.user_not_found"] = ("Nincs ilyen felhasználó a belépési előzményben: {ref}", "No such user in the logon history: {ref}"),
        ["log.updates"] = ("Biztonsági frissítések referenciaadata letöltve: {builds} Windows-build ({months})", "Security-update reference data downloaded: {builds} Windows build(s) ({months})"),
        ["err.updates_fetch"] = ("A Microsoft frissítési adatai nem tölthetők le (internet / proxy?): {err}", "The Microsoft update data could not be downloaded (internet / proxy?): {err}"),
        ["log.logins"] = ("Bejelentkezések követése: {imported}/{found} fájl beolvasva, {unknown} ismeretlen gép, {failed} hibás", "Login tracking: {imported}/{found} files read, {unknown} unknown computers, {failed} invalid"),
        ["err.logins_no_path"] = ("Előbb add meg a bejelentkezések mappáját (közös mappa) a Beállításokban.", "Set the login-tracking folder (a shared folder) in the Settings first."),
        ["err.sync_key_short"] = ("A szinkronkulcs legalább {n} karakter legyen (használd az „Erős kulcs generálása” gombot).", "The sync key must be at least {n} characters (use “Generate a strong key”)."),
        ["log.offline"] = ("Fájlos gyűjtés: {imported}/{found} fájl beolvasva, {unknown} ismeretlen gép, {failed} hibás", "File collection: imported {imported} of {found} file(s), {unknown} unknown computer(s), {failed} failed"),
        ["err.software_not_found"] = ("Nincs ilyen szoftver: {ref}", "No such software: {ref}"),
        ["err.cve_not_found"] = ("Nincs ilyen sebezhetőség a telepített szoftverek között: {ref}", "No such vulnerability among the installed software: {ref}"),
        ["err.proxy_407"] = ("A proxy hitelesítést kér (407). Adja meg a proxy felhasználónevét (felhasználó@tartomány vagy TARTOMÁNY\\felhasználó) és jelszavát a Beállítások → Proxy alatt. Basic vagy Digest hitelesítésű proxynál ez kötelező: ott a Windows-bejelentkezés nem használható. Hogy a proxy melyiket kéri, a Beállítások → Proxy → „Proxy teszt” megmutatja.", "The proxy asks for authentication (407). Enter the proxy user name (user@domain or DOMAIN\\user) and password under Settings → Proxy. A proxy with Basic or Digest authentication always needs them: the Windows logon cannot be used there. Settings → Proxy → \"Test proxy\" shows which one the proxy asks for."),
        ["proxy.source_explicit"] = ("Proxy: {proxy} (a Beállításokban megadott cím)", "Proxy: {proxy} (the address set in Settings)"),
        ["proxy.source_pac"] = ("Proxy: {proxy} (a PAC fájl választotta)", "Proxy: {proxy} (chosen by the PAC file)"),
        ["proxy.source_system"] = ("Proxy: {proxy} (a Windows proxybeállítása)", "Proxy: {proxy} (Windows' proxy settings)"),
        ["proxy.none"] = ("Nincs proxy: a kapcsolat közvetlenül megy.", "No proxy: the connection goes direct."),
        ["proxy.no_auth"] = ("A proxy nem kér bejelentkezést.", "The proxy does not ask for a login."),
        ["proxy.schemes"] = ("A proxy ezeket a hitelesítési módokat fogadja: {schemes}", "The proxy accepts these authentication methods: {schemes}"),
        ["proxy.schemes_unknown"] = ("A proxy hitelesítési módja nem állapítható meg: {err}", "Could not find out how the proxy authenticates: {err}"),
        ["proxy.cred_account"] = ("A program ezt a fiókot küldi a proxynak: {user}", "ADmiral sends this account to the proxy: {user}"),
        ["proxy.cred_windows"] = ("Nincs megadva proxyfiók: a program a Windows-bejelentkezést (Kerberos / NTLM) használja.", "No proxy account is set: ADmiral uses the Windows logon (Kerberos / NTLM)."),
        ["proxy.cred_none"] = ("A PAC fájl nem megbízható helyről jön (auto / http), ezért a program semmilyen fiókot nem küld ennek a proxynak.", "The PAC file comes from an untrusted place (auto / http), so ADmiral sends no account to this proxy."),
        ["proxy.need_account"] = ("A proxy csak jelszavas bejelentkezést fogad ({schemes}): adja meg fent a felhasználónevet (felhasználó@tartomány vagy TARTOMÁNY\\felhasználó) és a jelszót.", "The proxy only accepts a password login ({schemes}): enter the user name (user@domain or DOMAIN\\user) and the password above."),
        ["proxy.ok"] = ("✓ A kapcsolat működik ({target}, HTTP {code}).", "✓ The connection works ({target}, HTTP {code})."),
        ["proxy.failed"] = ("✗ A kapcsolat nem sikerült: {err}", "✗ The connection failed: {err}"),
        ["err.vulns_fetch"] = ("A CVE-adatok nem tölthetők le (internet / proxy?): {err}", "The CVE data could not be downloaded (internet / proxy?): {err}"),
        ["log.vulns"] = ("CVE-adatok letöltve: {n} termék frissítve ({mapped} ismert program), {errors} hiba", "CVE data downloaded: {n} product(s) updated ({mapped} known programs), {errors} error(s)"),
        ["err.pkg_folder"] = ("Adja meg a csomagmappát a Beállításokban (Csomagok).", "Set the package folder in Settings (Packages)."),
        ["log.pkg_upload"] = ("Csomagfájl feltöltve: {id} / {file}", "Package file added: {id} / {file}"),
        ["err.dep_no_targets"] = ("Válasszon ki legalább egy gépet.", "Select at least one computer."),
        ["err.dep_file"] = ("A kiválasztott fájl nem telepíthető (csak .msi és .exe).", "The selected file cannot be installed (only .msi and .exe)."),
        ["err.dep_hash"] = ("A(z) {file} fájl hash-e nem egyezik a nyilvántartással vagy a fájl hiányzik; a telepítés nem indult el.", "The hash of {file} does not match the register or the file is missing; the deployment was not started."),
        ["log.dep_start"] = ("Telepítés #{id} indult: {pkg}, {n} gép", "Deployment #{id} started: {pkg}, {n} computer(s)"),
        ["log.dep_done"] = ("Telepítés #{id} befejeződött: {status}", "Deployment #{id} finished: {status}"),
        ["log.pkg_remove"] = ("Csomag eltávolítva: {id}", "Package removed: {id}"),
        ["log.pkg_remove_file"] = ("Fájl eltávolítva a csomagból: {id}, {file}", "File removed from the package: {id}, {file}"),
        ["log.pkg_vendor"] = ("Gyártói hash egyezik: {id}, {file}", "Vendor hash matches: {id}, {file}"),
        ["err.dep_running"] = ("A telepítés még fut.", "The deployment is still running."),
        ["err.dep_no_failed"] = ("Nincs sikertelen gép ebben a telepítésben.", "There is no failed computer in this deployment."),
        ["dep.close_confirm"] = ("Telepítés van folyamatban ({n} gépen még nem fejeződött be). Ha most bezárja az ADmiralt, a követés megszakad, és a még nem végzett gépek sikertelennek lesznek jelölve (a már elindított telepítők a gépeken befejezhetik a munkájukat).\n\nMegszakítja a telepítést és bezárja a programot?", "A deployment is in progress ({n} computer(s) not finished). If you close ADmiral now, tracking stops and the unfinished computers will be marked as failed (installers already started may still finish on the computers).\n\nCancel the deployment and close the program?"),
        ["err.printer_dup"] = ("A(z) {ip} nyomtató már szerepel a listában.", "The printer {ip} is already in the list."),
        ["log.printer_add"] = ("Nyomtató felvéve: {ip}", "Printer added: {ip}"),
        ["log.printer_scan"] = ("Nyomtatókeresés: {range} ({n} cím, {found} nyomtató)", "Printer scan: {range} ({n} addresses, {found} printer(s))"),
        ["err.printer_ver"] = ("Az SNMP verzió csak 1 vagy 2c lehet.", "SNMP version must be 1 or 2c."),
        ["log.printer_delete"] = ("Nyomtató törölve: {ip}", "Printer removed: {ip}"),
        ["log.pkg_verify"] = ("Csomagok ellenőrzése: {n} csomag, {bad} hibás", "Packages verified: {n}, {bad} with problems"),
        ["log.service"] = ("Újrapróbáló szolgáltatás: {what}", "Retry service: {what}"),
        ["log.retry"] = ("Újrapróbálás (szolgáltatás): {n} gép – {online} elérhető, {collected} begyűjtve, {failed} sikertelen", "Retry (service): {n} computer(s) – {online} reachable, {collected} collected, {failed} failed"),
        ["log.collect_none"] = ("Nincs elérhető gép; előbb futtasson elérhetőség-ellenőrzést", "Nothing reachable; run a reachability scan first"),
        ["log.cleanup"] = ("{host}: önellenőrzés – szolgáltatás: {service}, törölt maradék fájl: {removed}, megmaradt fájl: {left}, leállított folyamat: {killed}{errors}", "{host}: self-check – service: {service}, leftover files removed: {removed}, files still there: {left}, process stopped: {killed}{errors}"),
        ["cleanup.service.absent"] = ("nincs (rendben)", "gone (ok)"),
        ["cleanup.service.removed"] = ("megmaradt, leállítva és törölve", "was left behind, stopped and deleted"),
        ["cleanup.service.failed"] = ("nem sikerült törölni", "could not be removed"),
        ["cleanup.errors"] = ("; hibák: {errors}", "; errors: {errors}"),
        ["state.yes"] = ("igen", "yes"),
        ["state.no"] = ("nem", "no"),
        ["log.tag"] = ("Címkék {changes} – {n} gépen", "Tags {changes} on {n} computer(s)"),
        ["log.fleet_create"] = ("{kind} gyűjtemény létrehozva: „{name}”", "{kind} collection '{name}' created"),
        ["log.fleet_update"] = ("„{name}” módosítva: {fields}", "'{name}' updated: {fields}"),
        ["log.fleet_delete"] = ("„{name}” gyűjtemény törölve", "Collection '{name}' deleted"),
        ["log.fleet_members"] = ("„{name}” tagjai: +{added} -{removed}", "'{name}' members: +{added} -{removed}"),
        ["log.export"] = ("„{name}” exportálva ({fmt}, {n} cél)", "'{name}' exported as {fmt} ({n} targets)"),
        ["log.settings"] = ("Beállítások mentve ({mode} mód)", "Settings saved ({mode} mode)"),
        ["log.settings_mode"] = ("; futtasson AD szinkronizálást az új címtár betöltéséhez", "; run Sync AD to load the new directory"),
        ["log.allow_scan"] = ("Szkennelés {state} {n} gépen", "Scanning {state} on {n} computer(s)"),
        ["state.enabled"] = ("engedélyezve", "enabled"),
        ["state.disabled"] = ("letiltva", "disabled"),
        ["scope.all"] = ("összes engedélyezett gép", "all enabled computers"),
        ["scope.fleet"] = ("„{name}” gyűjtemény", "collection '{name}'"),
        ["scope.selection"] = ("{n} kijelölt gép", "{n} selected computer(s)"),
        ["kind.static"] = ("Statikus", "Static"),
        ["kind.dynamic"] = ("Dinamikus", "Dynamic"),
        ["err.computer_not_found"] = ("A számítógép nem található: {ref}", "Computer {ref} not found"),
        ["err.unknown_computers"] = ("Ismeretlen számítógép(ek): {names}", "Unknown computer(s): {names}"),
        ["err.fleet_not_found"] = ("A gyűjtemény nem található: {ref}", "Collection '{ref}' not found"),
        ["err.fleet_name_required"] = ("A gyűjtemény neve kötelező", "Collection name is required"),
        ["err.fleet_exists"] = ("Már létezik „{name}” nevű gyűjtemény", "A collection named '{name}' already exists"),
        ["err.fleet_kind"] = ("A típus csak 'static' vagy 'dynamic' lehet", "kind must be 'static' or 'dynamic'"),
        ["err.only_dynamic_rules"] = ("Csak dinamikus gyűjteménynek vannak szabályai", "Only dynamic collections have rules"),
        ["err.static_only"] = ("Tagokat csak statikus gyűjteményben lehet szerkeszteni; a dinamikus gyűjtemény a szabályait követi (tipp: használjon címkéket)", "Members can only be edited on static collections; dynamic collections follow their rules (tip: tag machines instead)"),
        ["err.no_group"] = ("A(z) „{name}” gyűjteményhez nincs AD csoport beállítva", "Collection '{name}' has no AD group configured"),
        ["err.group_not_found"] = ("A csoport nem található: {dn}", "Group not found: {dn}"),
        ["err.winrm_creds"] = ("Nincs megadva WinRM fiók (Beállítások → Leltár begyűjtése)", "WinRM credentials are not configured (Settings → Inventory collection)"),
        ["err.pdq_creds"] = ("A PDQ-módszerhez az AD fiók és jelszó megadása szükséges (Beállítások → Active Directory)", "PDQ-style collection needs the AD account and password (Settings → Active Directory)"),
        ["err.not_admin"] = ("A leltár begyűjtéséhez az AD fióknak adminisztrátori jogosultság kell a gép szervezeti egységén (OU) (vagy tartományi szintű: Domain Admins / Enterprise Admins / Administrators). {detail}", "Inventory collection requires the AD account to have administrative rights on the computer's organizational unit (or domain-wide: Domain Admins / Enterprise Admins / Administrators). {detail}"),
        ["err.not_admin_ou"] = ("Nincs adminisztrátori jogosultság a(z) {ou} szervezeti egységen: {detail}", "No administrative rights on organizational unit {ou}: {detail}"),
        ["log.remove"] = ("{n} gép eltávolítva a listából", "{n} computer(s) removed from the list"),
        ["log.restore"] = ("{n} eltávolított gép visszaállítva", "{n} removed computer(s) restored"),
        ["err.smb_kerberos_rejected"] = ("A(z) {host} nem fogadta el a Kerberos-jegyet (az SMB-kapcsolat NTLM-re váltott). Ennek oka általában, hogy a gép neve nem egyezik az AD-ben nyilvántartott névvel / SPN-nel (cifs/{host}), vagy az SPN kétszer szerepel. A gép SPN-jeit a „setspn -L {short}” parancs listázza (kell lennie HOST/{host} bejegyzésnek); vagy kapcsolja be a Beállítások → Active Directory → NTLMv2 tartalék jelölőnégyzetet.", "{host} did not accept the Kerberos ticket (the SMB session fell back to NTLM). This usually means the name does not match the computer's SPN registered in AD (cifs/{host}), or the SPN is duplicated. List the computer's SPNs with 'setspn -L {short}' (a HOST/{host} entry must exist), or tick Settings → Active Directory → NTLMv2 fallback."),
        ["err.settings_readonly"] = ("A beállítások itt csak olvashatók; szerkessze az admiral.toml fájlt és indítsa újra", "Settings are read-only here; edit admiral.toml and restart"),
        ["err.job_busy"] = ("Már fut egy ilyen feladat ({kind})", "A {kind} job is already running"),
        ["err.upd_not_installed"] = ("Csak a telepített program tud magától frissülni (a hordozható és a forráskódos változat nem)", "Only the installed program can update itself (not the portable or source version)"),
        ["err.upd_busy"] = ("Fut egy feladat (leltár, telepítés...): a frissítés várjon, míg befejeződik", "A job is running (inventory, deployment...): wait until it has finished"),
        ["err.upd_no_prev"] = ("A frissítési helyen nincs egyel régebbi verzió", "The update location has no previous version"),
        ["err.upd_none"] = ("Nincs újabb verzió", "There is no newer version"),
        ["log.app_update_found"] = ("Új ADmiral verzió érhető el: {version}", "A new ADmiral version is available: {version}"),
        ["log.app_update_run"] = ("ADmiral {version} telepítése indul ({rollback})", "Installing ADmiral {version} ({rollback})"),
        ["err.format"] = ("Ismeretlen exportformátum: {fmt}", "Unknown export format '{fmt}'"),
        ["rule.object"] = ("A szabálynak objektumnak kell lennie", "rules must be an object"),
        ["rule.match"] = ("Az egyezés csak 'all' vagy 'any' lehet", "match must be 'all' or 'any'"),
        ["rule.empty"] = ("Legalább egy feltétel szükséges", "rules need at least one condition"),
        ["rule.cond_object"] = ("{i}. feltétel: hibás formátum", "condition {i} must be an object"),
        ["rule.field"] = ("{i}. feltétel: ismeretlen mező: {field}", "condition {i}: unknown field '{field}'"),
        ["rule.op"] = ("{i}. feltétel: a(z) „{op}” művelet nem használható ehhez a mezőhöz ({field})", "condition {i}: operator '{op}' not valid for {field}"),
        ["rule.value"] = ("{i}. feltétel: érték megadása kötelező", "condition {i}: a value is required"),
        ["rule.number"] = ("{i}. feltétel: az értéknek számnak kell lennie", "condition {i}: value must be a number"),
        ["rule.regex"] = ("{i}. feltétel: hibás reguláris kifejezés: {err}", "condition {i}: bad regex: {err}"),
    };

    public static void SetLanguage(string? lang) => _lang = lang is "hu" or "en" ? lang : "hu";

    public static string Language => _lang;

    /// <summary>Translate <paramref name="key"/>; placeholders are <c>{name}</c>. Unknown keys return the key itself,
    /// a missing parameter leaves the text unformatted (like Python's str.format fallback).</summary>
    public static string T(string key, IReadOnlyDictionary<string, object?>? args = null)
    {
        if (!Messages.TryGetValue(key, out var entry)) return key;
        var text = _lang == "en" || string.IsNullOrEmpty(entry.Hu) ? entry.En : entry.Hu;
        if (args is null || args.Count == 0) return text;
        var missing = false;
        var result = Placeholder().Replace(text, m =>
        {
            if (args.TryGetValue(m.Groups[1].Value, out var v)) return Convert.ToString(v, CultureInfo.InvariantCulture) ?? "";
            missing = true;
            return m.Value;
        });
        return missing ? text : result;
    }

    /// <summary>Convenience overload: <c>T("log.x", ("total", 3), ("added", 1))</c>.</summary>
    public static string T(string key, params (string Name, object? Value)[] args)
        => T(key, args.Length == 0 ? null : args.ToDictionary(a => a.Name, a => a.Value));

    [GeneratedRegex(@"\{([A-Za-z_][A-Za-z0-9_]*)\}")]
    private static partial Regex Placeholder();
}
