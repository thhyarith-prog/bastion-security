<p align="center"><img src="assets/img/icon-bastion.png" width="96" height="96" alt="Bastion Security icon"></p>

<h1 align="center">Bastion Security</h1>

<p align="center">Lightweight, privacy-first WordPress security. Firewall, brute-force protection, two-factor login, malware and integrity scanning, vulnerability alerts, hardening and an activity log. Every feature is free.</p>

<p align="center">Version 1.1.8 · WordPress 6.0+ · PHP 7.4+ · GPL-2.0-or-later · by <a href="https://www.prasatdigital.com">Prasat Digital</a> · <a href="https://www.prasatdigital.com/plugins#bastion">Plugin page</a></p>

---

Bastion protects a WordPress site in layers:

**Firewall (runs before WordPress)**
* Blocks SQL injection, XSS, path traversal, file inclusion, PHP/OS command injection, object injection, Log4Shell, SSRF and header injection.
* Decodes layered URL/HTML encoding and SQL comment tricks before matching, so obfuscated payloads are caught.
* Administrators are verified from their login cookie and never inspected, and editors with `unfiltered_html` skip the XSS rules. That avoids the admin false positives that make other firewalls need a learning period. Learning mode is still available.
* Blocks executable uploads, including images with hidden PHP code, from anyone who is not an administrator.
* Blocks vulnerability scanners (sqlmap, WPScan, Nikto…) and probes for `.env`, `.git`, `wp-config` backups, SQL dumps, `debug.log` and known web shells.
* Rate limiting, 404-flood blocking and automatic blocking of repeat attackers. Uses APCu when available, otherwise small files.
* Spoof-resistant IP detection: a proxy header is only trusted when the request really comes from that proxy. Cloudflare ranges are built in.
* Country blocking through Cloudflare or a GeoIP server module, for the whole site or the login page only.
* Three protection levels: plugin, must-use loader (automatic), or `auto_prepend_file` (one click, .htaccess or .user.ini). Extended mode also covers PHP files that attackers request directly.
* One-click "Allow" on a blocked request to add a precise exception (path + parameter + rule).

**Comment spam shield**
* Stops comment bots without a CAPTCHA and without sending comments to an outside service: a hidden trap field, a one-time browser check fetched when someone starts writing (works with page caching), a minimum writing time and a per-IP limit.
* Comments that only look like spam (too many links, spam words, alphabets your visitors never use, a website link after you removed the field) go to the spam folder, so a real one can be rescued.
* Pingbacks, trackbacks and anonymous REST comments are switched off. A "watch only" mode logs what would be blocked.
* Clean up an old backlog in one go: Bastion checks every waiting comment, moves the spam to the spam folder and empties it, leaving real-looking comments for you.

**Visitor monitoring (privacy-first)**
* Visitors and page views today and over 30 days, who is on the site now, top pages, where visitors come from, countries (with Cloudflare), devices and browsers.
* No cookies and no IP addresses: each visitor is counted with a code made with a random key that is replaced every day. Respects Do Not Track and Global Privacy Control. Data stays in your database for 30 days. Off until you turn it on.

**Login security**
* Lockouts with progressive back-off for repeat offenders. Lockouts are enforced by the firewall, so locked-out bots never load WordPress.
* Instant lockout for attempts on non-existent default names (admin, root, test…). Guessing a username that does not exist counts double.
* Generic login errors, blocking of username discovery (`?author=N`, REST users list, user sitemap, oEmbed), and limits on password reset requests.
* XML-RPC restricted (no `system.multicall` amplification, no pingbacks) or disabled.
* **Two-factor authentication** with any authenticator app. The QR code is generated in the browser, so the secret never leaves your site. Includes 10 single-use backup codes, "trust this device", required 2FA per role with a grace period, and secrets encrypted at rest with AES-256-GCM. It works with any login form that uses `wp_signon` (WooCommerce, page builders).
* Password policy per role and a breached-password check through Have I Been Pwned k-anonymity: only 5 characters of a hash are sent.
* Email alert when an administrator signs in from a new IP.

**Scanner**
* Compares every WordPress core file **and every WordPress.org plugin file** with the official checksums. Matching files are trusted and skipped, so scans are fast and false positives are rare.
* Malware signatures that look for backdoor behaviour (decoders feeding `eval`, request data run as code, hidden includes, SEO-spam redirects, crypto miners…) and show the matching line.
* Finds PHP files in uploads, unknown files in core folders and PHP hidden inside images.
* **Known vulnerabilities** in core, plugin and theme versions, from the free WPVulnerability.net database (only slugs and versions are sent).
* Flags plugins that were closed on WordPress.org (often for security reasons) or abandoned for 2+ years.
* Scans posts and options for injected scripts.
* **Restore original** downloads the verified official copy of a modified core or plugin file. **Quarantine** moves a suspicious file somewhere it cannot run, and you can restore it later.
* The scanner is resumable and time-boxed, so it never hits PHP time limits on shared hosting. Scans run daily or weekly at a quiet hour.

**Hardening and auditing**
* Security score and checklist. Security headers, optional HSTS, file editor off, version hidden, PHP blocked in uploads (Apache/LiteSpeed rule written for you; an Nginx snippet is provided).
* Activity log of logins, user and role changes, plugin, theme and core changes, important settings and every firewall block, with CSV export.
* Alerts when an administrator account appears. Automatically reverts the "anyone can register + administrator default role" takeover trick.

## Installation

1. Download the latest release ZIP (or this repository as a ZIP and rename the folder to `bastion-security`).
2. In WordPress go to **Plugins → Add New → Upload Plugin**, choose the ZIP and click **Install Now**.
3. Activate it. It appears under the **Prasat Digital** menu, together with the other Prasat Digital plugins you use.

## The Prasat Digital plugin family

| Plugin | What it does |
|---|---|
| [Bastion Security](https://github.com/thhyarith-prog/bastion-security) | Firewall, login security, malware scan, comment spam shield, visitor stats |
| [Lifeboat Backup](https://github.com/thhyarith-prog/lifeboat-backup) | Automatic cloud backups and one-click restore |
| [Slipstream](https://github.com/thhyarith-prog/slipstream) | Page cache and speed optimizations |
| [Compass](https://github.com/thhyarith-prog/compass) | SEO: titles, descriptions, schema, sitemap, redirects |
| [Featherweight](https://github.com/thhyarith-prog/featherweight) | WebP images and WebM videos |

All five share one **Prasat Digital** menu with a one-click **Check my website** score.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).

---

<p align="center"><em>“Every website deserves to stand strong, load fast and stay safe.”</em><br>Made by <a href="https://www.prasatdigital.com">Prasat Digital</a> · Founded by Thyyarith</p>
