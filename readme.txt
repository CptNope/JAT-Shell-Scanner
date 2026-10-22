=== wp2shell Scanner ===
Contributors: cptnope
Tags: security, malware, scanner, webshell, wp2shell
Requires at least: 6.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Checks your site for signs of the wp2shell attack on WordPress core (CVE-2026-63030 / CVE-2026-60137). Read-only.

== Description ==

wp2shell is a vulnerability chain in WordPress core, made public on July 17, 2026, that lets anyone take over an unpatched site without logging in. This plugin checks whether your site is vulnerable and whether it shows signs of having been attacked.

The scan only reads. It never changes or deletes anything.

It checks:

* Your WordPress version (6.9.0–6.9.4 and 7.0.0–7.0.1 fully vulnerable; 6.8.0–6.8.5 partly)
* Plugins dropped by the attack, and plugins hidden from the Plugins screen
* PHP files in uploads, cache and upgrade folders, hidden PHP files and .htaccess tricks
* Known webshell code patterns and file hashes
* Administrators and application passwords created since July 17, 2026
* WordPress core files against official checksums
* Your web server access log, if PHP can read it

Features:

* Works on shared hosting with short time limits — scans run in slices with a progress bar
* Weekly or daily automatic scans with email alerts for new, serious findings
* Ignore false positives
* Site Health integration
* WP-CLI: `wp wp2shell scan`, `status`, `ignore`
* Multisite aware
* Updates automatically from GitHub releases

== Installation ==

1. Upload the zip under Plugins → Add New Plugin → Upload Plugin, and activate.
2. Go to Tools → wp2shell Scanner and click Scan now.

On multisite, network-activate and use Network Admin → Settings → wp2shell Scanner.

== Frequently Asked Questions ==

= Will it change or delete my files? =

No. It only reads and reports. You decide what to remove.

= It says "Vulnerable". Was I hacked? =

Not necessarily. "Vulnerable" means there's no evidence of an attack, but your WordPress version can be attacked this way. Update WordPress, then scan again.

= Something it flagged is mine. =

Click Ignore next to it. It won't affect the result or send alerts again.

= Does it send my data anywhere? =

No. The only outside requests are core checksums from wordpress.org and a twice-daily update check to GitHub.

== Changelog ==

= 1.0.0 =
* First public release.
