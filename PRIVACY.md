# Privacy

ADmiral works inside your network, and what it learns there stays there.

## The short version

- No telemetry. No analytics, no usage statistics, no crash reports sent anywhere.
- What ADmiral reads from AD and collects from your computers stays on your machine. It's only shared with other
  ADmiral instances you set up yourself.
- Installer downloads are counted as one anonymous number that only goes up. Update checks aren't counted.
- Update checks can be switched off in Settings, and then ADmiral doesn't contact our server at all, not even at
  startup.

## Your data stays with you

There are no telemetry, analytics or advertising components in ADmiral. What it reads from Active Directory or
collects from your computers (computer and user names, OUs, inventory, installed software, deployment results, logs)
is never sent to Tidecrest Labs or to anyone else.

Everything lives in the data folder (`C:\ProgramData\ADmiral` by default, or the folder you picked in the
installer). Saved passwords go into `secrets.json`, encrypted with Windows DPAPI.

Data only leaves that folder when you make it:

- **Sync** - computers, collections, users and printers are shared only with the peers you listed, over your own
  network, encrypted with keys derived from the shared key you set. Settings and passwords are never synced.
- **Exports and error reports** - exported files and the error report you copy from **Settings** go only where you
  put them. The report is anonymized and passwords are masked. The GitHub issue button just opens a page in your
  browser; nothing is posted until you post it.
- **Offline inbox and logon tracking** - if you set them up, computers write files into a shared folder you chose, on
  your network.

The About and Support windows link to the website, Ko-fi and Discord. Those only open when you click them; ADmiral
doesn't contact those sites by itself.

## Public data lookups

To show vulnerabilities and Windows update status, ADmiral downloads public data from:

- NIST NVD
- CISA (Known Exploited Vulnerabilities)
- the Microsoft MSRC API

These requests only fetch public information and carry nothing about your network. Like any website, those services
see connection data such as your IP address, and handle it under their own privacy policies.

## Update checks

Update checks are on by default. ADmiral checks at startup, every 24 hours after that, and when you click **Check for
updates**.

- It downloads a small signed file, `latest.json`, from `tidecrestlabs.com/admiral/releases/`.
- If there's a newer version and you choose to install it, the installer comes from the same place. Its signature and
  SHA-256 are checked before anything runs.
- The update address is built into the app and can't be changed, on purpose.
- Our server sees your IP address, the time and a User-Agent of `ADmiral/<version>`. No AD, inventory or settings
  data is sent. We don't keep request logs.

### Switching them off

Go to **Settings -> Program updates** and untick *Look for a new version at start-up and every 24 hours*. ADmiral
then doesn't contact our server at all, startup included. The manual **Check for updates** button still works.

Update checks can go through a proxy (PAC/WPAD works too). If you'd rather update by hand, download the new
installer from the website or [Releases](../../releases) and run it over the old version.

## What we keep: one download counter

The only thing we keep is a single running total that goes up by one per counted download. No IP addresses, no
timestamps, no User-Agents, nothing per request. It can't even be split by day or week.

What counts:

- Downloading the installer from the download page.
- The built-in updater downloading an installer that passes the SHA-256 check. ADmiral then sends one empty request
  to `count.php` (no body, just a "verified" header and the User-Agent). Broken downloads aren't counted.

What doesn't count: update checks (fetching `latest.json`) and resumed broken downloads.

Since there are no request logs, there's nothing to store, analyse or delete later. The counter isn't shared, sold or
handed to anyone. Downloads from GitHub Releases go to GitHub and fall under GitHub's own privacy statement.

## The website

[tidecrestlabs.com](https://tidecrestlabs.com) sets no cookies and has no analytics or ads.

- Your language and theme choices are kept in your browser's local storage and aren't sent anywhere.
- Fonts load from Google Fonts, so Google sees your IP address when a page loads.
- The download page reads `latest.json` and the counter from our own server.
- Starting a download shows a small window suggesting Ko-fi support. It's just a link; nothing goes to Ko-fi unless
  you click it, and then Ko-fi's own policy applies.

## Changes and contact

If this policy changes, the new version shows up here and on
[tidecrestlabs.com/admiral/privacy](https://tidecrestlabs.com/admiral/privacy/) with a new date. Important changes
are also mentioned in the release notes.

Questions? Open an [issue](../../issues). Please don't post anything from your environment (computer names, user
names, logs) in a public issue. Security problems go through a private report instead, see
[SECURITY.md](SECURITY.md).

*Last updated: 22 November 2026 (ADmiral 0.6.0)*
