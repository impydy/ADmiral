# Setting things up

A few parts of ADmiral need a bit more than filling in a form. Here's how to get them going.

## The collection account

To read inventory and to deploy, ADmiral needs an account that's a local admin on the target computers. A
dedicated domain service account added to the computers' local Administrators group (via GPO) works well.

By default ADmiral connects to `\\computer\ADMIN$`, drops a small read-only script into its own private folder
(`C:\Windows\ADmiral\<random>`, admins only), runs it once through a temporary service, reads the result and cleans
up. If you'd rather use WinRM, switch **Settings -> Inventory collection -> Method** to WinRM.

- Kerberos is the default and the recommended choice. Use host names that match the computers' names in AD, or
  Kerberos won't find the right SPN.
- NTLMv2 is only used if you tick the fallback, and only after Kerberos really refused the login (never just
  because a server was unreachable).
- WinRM `basic`/`ssl` sends the password in a readable form, so ADmiral only allows it over HTTPS.

## Computers that can't be reached (offline inbox)

Some machines sit behind a VPN or a firewall that ADmiral can't get through. They can send their inventory as a file
instead:

1. Make a shared folder, e.g. `\\fileserver\admiral-inbox`.
2. Set its **NTFS** permissions like this (this matters, ADmiral checks it and refuses to import otherwise):
   - Domain Computers: *Create files / write data*, **this folder only**
   - CREATOR OWNER: *Modify*, **files only**
   - SYSTEM, Administrators and the account ADmiral runs as: *Full control*
   - nobody else
   Turn on SMB signing (or encryption) for the share too.
3. In ADmiral, **Settings -> File collection**: enter the folder, then save the `ADmiral-Collect.ps1` script.
4. Put the script into a GPO as a **computer Startup script** (Computer Configuration -> Policies -> Windows Settings
   -> Scripts -> Startup -> PowerShell Scripts) with the parameter `-OutputPath \\fileserver\admiral-inbox`. Keep the
   script in the GPO's SYSVOL folder, never in the inbox itself.

Each computer writes `<NAME>.admiral.json`, and ADmiral picks it up on start, on the button, and in every round of
the retry service. A file only counts for the computer whose account wrote it, so one machine can't send in fake data
for another. Files planted under someone else's name, broken files and older-than-current files are deleted.

If you can only run it as a user Logon script, tick *Accept files written by user accounts*. Be aware that then any
domain user could hand in a file for any computer.

## Login tracking

When a computer's event log can't be read remotely, the login tracking script can record logons into a shared folder
instead (**Settings -> Login tracking**). Same folder permissions as above.

## The retry service

ADmiral can install a small Windows service ("ADmiral retry") that keeps going while the window is closed: it retries
the computers that were offline or failed, reads the inboxes, and (with sync on) listens for the other instances and
runs the automatic sync. **Settings -> Retry service -> Install**. It runs as the account you give it (by default the
saved AD account), so install ADmiral with the installer first: running a service from a folder every user can change
would be a bad idea, and ADmiral won't do it.

## Sync between ADmiral instances

If more than one admin runs ADmiral (say, one per site), they can share computers, collections, users and printers.

1. **Settings -> Synchronisation**: turn it on, and type the same shared key (at least 16 characters, longer is better) on
   every instance.
2. List the peers (`host` or `host:port`).
3. The allowed network defaults to your own `/24`. Widen it if the peers are elsewhere.

What to know:

- Everything is encrypted and authenticated with keys derived from the shared key. Wrong key = nothing happens.
- Settings and passwords are never synced.
- A computer that only a peer knows about isn't scanned or deployed to until your own AD sync sees it too. A peer
  can't change what your AD says about a computer (name, host, OU, OS...).
- Collections and tags do sync. If a peer changed a collection, or tagged a computer, and nobody edited it on your
  side since, the deploy confirmation will tell you, so you can double-check before you install something.

## Packages and deployments

Add installers to the package library (**Packages -> Add file...**), with the vendor's SHA-256 if you have it. When you deploy, ADmiral re-checks the file's hash, copies it to each machine, runs it with the switches you
picked (presets for the usual silent switches are there), and collects the exit codes and logs.

Before anything starts, the confirmation lists every target computer by name. Read it. :)

## App updates

ADmiral checks for new versions on its own and shows them in Settings. The update manifest is signed, the installer's
hash has to match, and old manifests can't be replayed to push you back to an older version. Installing an update
asks for admin rights (UAC).
