# ADmiral

ADmiral is a little Windows tool for keeping an eye on the computers in an Active Directory domain. It reads your
AD, checks which machines are up, pulls an inventory from each one (hardware, software, services, updates, who logs
on), and lets you push installers out to them. No agent to install on the clients: it uses what Windows already has
(SMB + the Service Control Manager, or WinRM).

If you've used PDQ Inventory / PDQ Deploy, the idea will feel familiar. This is a smaller, free, open-source take
on it for small and mid-sized networks.

The UI speaks Hungarian and English.

## What it can do

- **Computers** - everything in AD, grouped by OU, with online/offline state, last logon, OS, disks, NICs,
  installed software, services, local admins and logon history.
- **Collections** - static lists or dynamic ones built from rules ("OS contains Windows 10 and OU is Sales").
  Compare a collection with an AD group (read-only, nothing is written to AD).
- **Software & vulnerabilities** - what's installed where, matched against known CVEs (NVD + CISA KEV).
- **Windows updates** - which machines are behind on Microsoft's monthly security releases.
- **Deployments** - push an `.msi` or `.exe` from your package library to a selection of machines and watch the
  results come in. Failed ones can be retried with one click.
- **Printers** - poll network printers over SNMP for toner levels and page counts, with a simple forecast.
- **Users** - AD users and where they've logged on.
- **Offline computers** - machines that can't be reached directly can drop their inventory into a shared folder
  with a small PowerShell script (more in [docs/setup.md](docs/setup.md)).
- **Sync** - several ADmiral instances on the same network can share what they've found, encrypted with a shared
  key.
- **Exports** - any list to XLSX, and collections as TXT, CSV, JSON, an Ansible inventory or a PowerShell list.

ADmiral never writes to Active Directory. It only reads.

## Getting it

Grab the installer (`ADmiral-Setup-<version>.exe`) from the [Releases](../../releases) page and run it. It's a
self-contained build, so you don't need to install .NET. It does need the WebView2 runtime; the installer sets it up
if it's missing (Windows 10/11 usually have it already).

After the first start, open **Settings** and fill in:

1. **Active Directory** - your domain controller and the search base (e.g. `DC=contoso,DC=local`). Kerberos is the
   default and works with the logged-on user. A plain read-only account is enough for reading AD.
2. **Inventory collection** - to read inventory from the computers you need an account that's a local admin on them
   (usually a dedicated service account). Inventory goes over `ADMIN$` + a short-lived service by default, or WinRM
   if you prefer.

Then hit **AD sync**, then **Scan** - and you should see your machines fill up.

Want to look around first? Put `mode = "demo"` into `admiral.toml` and you get a made-up domain with ~190 computers
to click through.

## Where things live

- Program: wherever you installed it (Program Files by default).
- Data (database, settings, logs): `%APPDATA%\ADmiral`, or the shared data folder you picked in the installer.
- Settings: `admiral.toml` in the data folder. Passwords aren't stored there; they go into `secrets.json`, encrypted
  with Windows DPAPI.
- Logs: `logs\admiral.log` in the data folder (rotates at 10 MB). **Settings -> Diagnostics** shows a grouped error
  report you can copy into an issue; it's anonymized for you.

## Command line

There's also a command-line tool, `admiral`, which is handy for scheduled tasks or running without the window:

```
admiral init              # write an example admiral.toml
admiral test              # check the AD connection
admiral refresh           # AD sync + scan + collect, good for a scheduled task
admiral list --fleet "Sales laptops"
admiral export "Sales laptops" --format csv
admiral serve             # the web UI in your browser instead of the window
admiral --help            # everything else
```

## Building it yourself

You need the [.NET 10 SDK](https://dot.net).

```
dotnet build ADmiral.slnx
dotnet test tests/ADmiral.Tests
dotnet run --project src/ADmiral.Cli -- serve
```

The tests run on Linux too. A few extras are optional: the PowerShell tests need `pwsh`, and the browser UI test
needs Node + Playwright (`npm i -g playwright && playwright install chromium`). Tests that need real Windows bits are
skipped elsewhere.

The Windows installer is built on Windows with `packaging\build.ps1` (needs Inno Setup 6). The GitHub workflow in
`.github/workflows/build-exe.yml` does the same thing on every push, and publishes a release when you push a
`v<version>` tag.

### How the code is laid out

| Folder | What's in it |
|---|---|
| `src/ADmiral.Core` | the engine: settings, SQLite store, AD reading, scan / collect / deploy, packages, sync, updates, vulnerabilities, printers, rules |
| `src/ADmiral.Web` | the local web API + the HTML/JS UI (`wwwroot`), and the sync listener |
| `src/ADmiral.Cli` | the `admiral` command line |
| `src/ADmiral.Desktop` | `ADmiral.exe`: the window (WinForms + WebView2) and the background retry service |
| `tests/ADmiral.Tests` | xUnit tests |
| `packaging/` | build script, Inno Setup installer, EULAs, release notes |
| `scripts/` | the offline collector script and the release signing tool |

## Security, in short

ADmiral handles admin credentials and runs things on your machines, so it tries hard not to be the weak spot:

- AD access is read-only, always.
- The UI talks to a local API on a random port with a fresh token every launch, so other users and web pages
  can't poke at it.
- Passwords are DPAPI-encrypted, never in the config file, never in logs.
- Installers are hash-checked right before they're sent, and remote runs use a private, admin-only folder.
- App updates are signed (Ed25519) and checked before anything runs.
- Sync traffic is encrypted and authenticated, and a peer can never decide where ADmiral sends your admin
  credentials.

More details, and how to report a problem, are in [SECURITY.md](SECURITY.md).

## Support

Found a bug or have an idea? Open an issue. If ADmiral saves you some time and you feel like it, there's a Ko-fi link
in the app. :)

## License

GPL-3.0, see [LICENSE](LICENSE).
