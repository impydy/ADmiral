# Security

ADmiral works with admin credentials and runs things on your computers, so security bugs are taken seriously.

## Found something?

Please don't post the details in a public issue. Use GitHub's **Report a vulnerability** button on the Security tab
of this repository instead (private advisory). If that's not available, open an issue that just says you've found
something and how to reach you, and we'll take it from there.

Handy to include: the ADmiral version (see the About box), what you did, what happened, and what you expected.

## What ADmiral does to keep you safe

**Active Directory**
- Only reads. There's no code path that writes to AD.
- LDAPS certificates are checked by default; simple binds are only allowed over LDAPS.
- Kerberos first. NTLMv2 only if you allow it, and only after Kerberos really refused the login, so an attacker
  can't force a downgrade by blocking the KDC.

**The app itself**
- The UI talks to a local API on `127.0.0.1` with a random port and a new token each launch, plus Host / Origin /
  CSRF checks, so other users and web pages can't use it.
- Strict Content-Security-Policy and Trusted Types in the UI, and the window only navigates to its own pages.
- Passwords live in `secrets.json`, encrypted with DPAPI. They're never in `admiral.toml` and they're scrubbed from
  logs and diagnostic reports.
- The data folder gets a locked-down ACL, and ADmiral refuses a data or program folder that ordinary users could
  change.

**Remote computers**
- Remote runs happen in a fresh, randomly named folder that only admins can touch, through a short-lived service.
- Installers are hashed while they're copied, so what runs is exactly what you approved.
- Installer arguments can't break out into extra commands.
- WinRM Basic auth is only allowed over HTTPS.

**Offline inbox and login tracking**
- A file only counts for the computer account that wrote it (checked by SID), so machines can't report for each
  other.
- ADmiral won't import from a folder whose permissions let computers change or delete each other's files.
- Planted, broken or stale files are removed, so nobody can block another computer's delivery.

**Sync**
- AES-256-GCM with keys derived from your shared key (PBKDF2, 600k rounds + HKDF), replay protection, size and rate
  limits.
- Only peers inside the allowed network can even open a connection, and one address can't hog all the slots.
- Peers never get your settings or passwords, can't decide where your admin credentials are sent, and can't
  change what your AD says about a computer. Collection and tag changes from peers are flagged before a deployment.

**Updates**
- Update manifests are signed with Ed25519 and expire; installers must match the signed SHA-256 and are re-checked
  right before they start.
- Older manifests can't be replayed to roll you back to an old version.

## Things to keep in mind

- Whoever holds the sync key is treated as a fellow admin. Pick a long key and don't share it around.
- Turning on *Accept files written by user accounts* lets any domain user send in a file for any computer.
- Some parts (the native Windows SMB/service code, real Kerberos/LDAPS) can only really be tested on Windows in a
  domain. If you see something odd there, please tell us.
