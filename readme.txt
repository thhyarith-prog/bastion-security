=== Bastion Security ===
Tags: security, firewall, two-factor, malware scanner, brute force
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.8
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight, privacy-first WordPress security. Firewall, brute-force protection, two-factor login, malware and integrity scanning, vulnerability alerts, hardening and an activity log. Every feature is free.

== Description ==

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

== Compared with Wordfence (free) ==

Bastion is better for:

* No account, no license key and no cloud dashboard: everything runs on your server.
* 2FA, country blocking and the vulnerability database, which are premium-only or limited in some security plugins, are included free.
* Plugin file integrity is checked against WordPress.org checksums, and closed plugins are flagged.
* The firewall verifies administrators instead of needing a learning week.
* A small footprint: no large signature downloads and no scan-result tables of millions of rows.

Wordfence is still stronger at:

* Real-time threat intelligence. Wordfence Premium pushes new firewall rules and malware signatures and keeps an IP blocklist built from millions of sites. Bastion's rules and signatures change only when the plugin is updated, and it has no shared attacker blocklist.
* The size of its malware signature database.
* Years of real-world testing against false positives across many hosting setups. Bastion is new.

== Installation ==

1. Upload the `bastion-security` folder to `/wp-content/plugins/` and activate it.
2. The firewall and login protection start right away. Open **Bastion → Dashboard**.
3. Run the first scan, set up two-factor on your profile, and on **Firewall** click **Enable extended protection**.
4. Running another firewall plugin that uses `auto_prepend_file`? Bastion detects it and will not overwrite it.

== Frequently Asked Questions ==

= I locked myself out =
Delete `wp-content/bastion-waf/blocks.php` to clear all blocks. To bypass the firewall completely, delete `bastion-waf-prepend.php` from the site root and `wp-content/mu-plugins/bastion-waf-loader.php`, or rename the plugin folder.

= I lost my phone =
Use one of your backup codes. Another administrator can also turn off two-factor for you from your user profile.

= Visitors all show the same IP =
Your site is behind a proxy. On **Firewall**, set "How to get visitor IPs" to X-Forwarded-For and add the proxy address under Trusted proxies.

= What leaves my server? =
Only these, and only when the matching feature is on: requests to WordPress.org for checksums and plugin status, WPVulnerability.net for slugs and versions, and Have I Been Pwned for a 5-character hash prefix when a password is set. Bastion has no telemetry.

== Credits ==

* Interface fonts: Inter (The Inter Project Authors) and Noto Sans Khmer (Google), SIL Open Font License 1.1, bundled in assets/fonts.

== Changelog ==

= 1.1.8 =
* Improved: links to a plugin now open its own section of prasatdigital.com/plugins (overview cards, dashboard tiles, the health check and "Visit plugin site").

= 1.1.7 =
* Fixed: on servers that ignore the extended-firewall setting, Bastion no longer says "activating" forever. After 10 minutes it tries the other way (.user.ini or .htaccess); Smart AI Optimize does this for you, or use "Try another way" on the Firewall screen.
* Fixed: if the server allows neither way, Bastion says so plainly and stops listing it as a problem. Standard protection, which runs before every other plugin, stays on.
* Fixed: the Firewall screen now names the file that was actually used.

= 1.1.6 =
* New: "Optimize with AI" now fixes what is safe to fix, not just lists it. It backs up first with Lifeboat, makes the safe fixes, shows each change under "Fixed for you" with an Undo button, then the AI writes a plan for what is left.
* New: Bastion fixes it can make for you: moves waiting spam comments to the Spam folder (nothing is deleted), turns on the comment spam shield, switches the firewall from learning to blocking, and sets the firewall to run before WordPress (taken back at once if the site does not load).

= 1.1.5 =
* New: if a file Bastion quarantined turns out to be one your site needs to run, Bastion puts it back automatically. You see one error page, and the next reload works again. The activity log records which file was put back.
* Improved: the quarantine warning now suggests updating the theme or plugin instead when the file belongs to one you trust.
* Improved: the "Optimize with AI" button has a new Prasat temple design that builds up while your plan is being written and shows a tick when it is ready.
* Improved: the plan now says which AI wrote it.

= 1.1.4 =
* New: Smart AI Optimize (Prasat Premium). Add your Premium key on the Prasat Digital dashboard, then "Optimize with AI" runs a fresh check and Claude writes a step-by-step plan for your site, with a button to each fix. Only scores and check titles are sent: no user names, emails, IP addresses or site address.
* Improved: "Check again" on Dashboard > Updates now looks for new Prasat releases straight away.

= 1.1.3 =
* New: the Prasat Digital overview is now a full dashboard: website health with a severity breakdown, "What to fix first", live tiles for every plugin, recent activity, 7-day charts and the Smart AI Optimize (Premium) card.
* New: Prasat temple loading animations for checks, scans, backups and every progress bar.
* New: attacks, visitors and running scans appear on the Prasat Digital dashboard.

= 1.1.2 =
* New: updates now come from the plugin's GitHub releases (github.com/thhyarith-prog), with the normal one-click "Update now" and automatic updates.

= 1.1.1 =
* Fix: the scanner no longer reports Prasat plugins (or any plugin with an Update URI) as closed or vulnerable because a different WordPress.org plugin shares the folder name.
* Fix: other security tools' rule files (Wordfence wflogs, Sucuri, NinjaFirewall…) are skipped, since they contain malware patterns on purpose.
* Fix: declares "Update URI", so WordPress never offers an unrelated WordPress.org plugin with the same folder name as an update for this one.

= 1.1.0 =
* New: comment spam shield (Comments tab): hidden trap field, one-time browser check that works with page caching, minimum writing time, per-IP limit, link and spam-word checks, optional alphabet filter and website-field removal, pingbacks and trackbacks off, "watch only" mode.
* New: "Clean up old spam" checks every waiting comment, moves the spam to the spam folder in bulk (without calling outside services) and empties it.
* New: privacy-first visitor monitoring (Visitors tab): live visitors, today vs yesterday, 7/30-day chart, top pages, referrers, countries, devices and browsers. No cookies, no IP addresses, 30 days.
* New: "Comments" filter in the activity log.
* New: reports to the one-click "Check my website" on the Prasat Digital page.

= 1.0.2 =
* New: a new app icon for Bastion Security and for the Prasat Digital menu, plus a short motto and credit (Made by Prasat Digital, founded by Thyyarith) at the bottom of every Prasat Digital screen.

= 1.0.1 =
* Fix: learning mode now only logs. Before, file probes, attack-tool user agents, XML-RPC abuse, the request rate limit, the 404 limit and username discovery still blocked visitors. Manual blocks, country blocks and login lockouts still apply.

= 1.0.0 =
* First release.
