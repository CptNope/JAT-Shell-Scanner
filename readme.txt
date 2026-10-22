=== PHP2Shell & wp2shell Scanner ===
Contributors: cptnope
Tags: security, php2shell, malware, scanner, webshell
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.0
Stable tag: 1.3.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Checks whether your site is exposed to — or was broken into through — PHP2Shell (a critical PHP bug, October 2026) and wp2shell (a WordPress bug, July 2026). Optional one-click fixes and a fleet dashboard.

== Description ==

**PHP2Shell** (CVE-2026-109618 / CVE-2026-109619) is a pair of critical bugs in PHP itself, made public on October 21, 2026 and attacked since October 17. It lets anyone run code on an unpatched server without logging in, and can leak passwords and keys from memory. It's fixed by updating PHP — usually your host's job — to 8.2.35, 8.3.36, 8.4.27, 8.5.12 or later.

**wp2shell** (CVE-2026-63030 / CVE-2026-60137) is a WordPress core bug from July 2026, fixed in WordPress 6.8.6, 6.9.5 and 7.0.2.

This plugin tells you whether your site is exposed to either, and looks for signs that an attacker already got in. Scans only read. If something is found, optional one-click fixes can quarantine files or remove admin rights — and every fix can be undone.

It checks:

* The PHP your website runs, including Debian/Ubuntu package versions and build dates (patched without a version change), and the temporary php.ini protections
* Whether the site ran an unpatched PHP during the attack window
* PHP2Shell traces in the PHP error log; exploit tools, known attacker addresses and suspicious bursts in the access log; the /tmp/nfs second stage
* Your WordPress version, and wp2shell exploit plugins, files and traffic
* Webshell code anywhere in the site, PHP hidden in uploads, images and the site root, and PHP auto-loaded via .user.ini / .htaccess
* New or promoted administrators, roles given admin powers, application passwords
* WordPress core files against official checksums
* Its own files, against the official release

Features:

* Works on shared hosting with short time limits — scans run in slices with a progress bar
* A ready-to-send message for your host when PHP needs updating
* Weekly or daily automatic scans with email alerts for new, serious findings
* One-click quarantine and admin removal, with undo
* Fleet dashboard: one hub site shows the results of all your sites, with email/Slack/Discord alerts and remote rescans
* Ignore false positives (signed, so attackers can't forge it)
* Site Health integration
* WP-CLI: `wp php2shell scan`, `status`, `ignore`, `fix`, `quarantine`, `fleet`
* Multisite aware
* Updates automatically from GitHub releases

== Installation ==

1. Upload the zip under Plugins → Add New Plugin → Upload Plugin, and activate.
2. Go to Tools → PHP2Shell Scanner and click Scan now.

On multisite, network-activate and use Network Admin → Settings → PHP2Shell Scanner.

== Frequently Asked Questions ==

= Will it change or delete my files? =

Scans never do. Only if you click a fix button does it move a file into quarantine (renamed so it can't run) or remove someone's admin rights — and you can undo either from the Quarantine tab.

= It says "Vulnerable — PHP needs updating". Was I hacked? =

Not necessarily. It means no signs of a break-in were found, but your server's PHP can be attacked. Send your host the ready-made message on the scanner page.

= My host says PHP is patched, but the scanner disagrees. =

Some hosts fix PHP without changing its version number. If your host confirms both CVEs are fixed, click Ignore on that finding.

= Does it send my data anywhere? =

No. The only outside requests are core checksums from wordpress.org and update/self-check requests to GitHub. If you set up a fleet, member sites send a short summary to your own hub site.

== Changelog ==

= 1.3.0 =
* Security fixes from an independent review: per-site fleet identities, safer quarantine and restore (no links, contents must match the scan), last admin never demoted.
* Fleet alerts (email, Slack, Discord) and "Scan again" for member sites.
* New PHP2Shell intel: Ubuntu ESM packages, more log, temp-folder, session and server checks.
* The page keeps your place after a fix.

= 1.2.0 =
* One-click fixes with undo: quarantine files and plugins, remove admin rights.
* Fleet dashboard for many sites.
* Latest PHP2Shell intel: Ubuntu/Debian package and build-date checks, exploit-tool and attacker-address detection, /tmp/nfs, fewer false alarms on patched PHP.
* Redesigned scanner page.

= 1.1.0 =
* PHP2Shell (CVE-2026-109618 / CVE-2026-109619) detection: PHP version and stopgaps, version history, error-log and access-log evidence, ready-made message for your host.
* Many new checks, fewer false alarms, and a much more robust scan engine. See CHANGELOG.md.

= 1.0.0 =
* First public release.
