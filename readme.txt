=== JAT Shell Scanner ===
Contributors: cptnope
Tags: security, malware, scanner, webshell, vulnerability
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.0
Stable tag: 1.6.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Checks if your site is exposed to, or was hacked through, PHP2Shell (critical PHP bug) and wp2shell (WordPress bug). Optional fixes you can undo.

== Description ==

**PHP2Shell** (CVE-2026-109618 / CVE-2026-109619) is a pair of critical bugs in PHP itself, made public on October 21, 2026 and attacked since October 17. It lets anyone run code on an unpatched server without logging in, and can leak passwords and keys from memory. It's fixed by updating PHP — usually your host's job — to 8.2.35, 8.3.36, 8.4.27, 8.5.12 or later.

**wp2shell** (CVE-2026-63030 / CVE-2026-60137) is a WordPress core bug from July 2026, fixed in WordPress 6.8.6, 6.9.5 and 7.0.2.

This plugin tells you whether your site is exposed to either, and looks for signs that an attacker already got in. Scans only read. If something is found, optional one-click fixes can quarantine files or remove admin rights — and every fix can be undone.

= What it checks =

* The PHP your website runs, including Debian/Ubuntu package versions and build dates (patched without a version change), and the temporary php.ini protections
* Whether the site ran an unpatched PHP during the attack window
* PHP2Shell traces in the PHP error log; exploit tools, known attacker addresses and suspicious bursts in the access log; the /tmp/nfs second stage
* Your WordPress version, and wp2shell exploit plugins, files and traffic
* Webshell code anywhere in the site, PHP hidden in uploads, images and the site root, and PHP auto-loaded via .user.ini / .htaccess
* New or promoted administrators, roles given admin powers, application passwords
* Backdoors kept in the database: code in settings, scripts and hidden links injected into posts, scheduled tasks that carry code
* WordPress core files, and plugins from WordPress.org, against official checksums; unexplained drop-ins
* Its own files, against the checksums WordPress.org publishes for this plugin

= Features =

* Works on shared hosting with short time limits — scans run in slices with a progress bar
* A ready-to-send message for your host when PHP needs updating
* Weekly or daily automatic scans with email alerts for new, serious findings
* One-click quarantine and admin removal, with undo
* Fleet dashboard: one hub site shows the results of all your sites, with email/Slack/Discord alerts and remote rescans
* Ignore false positives (signed, so attackers can't forge it)
* Site Health integration
* WP-CLI: `wp php2shell scan`, `status`, `ignore`, `fix`, `quarantine`, `fleet`
* Multisite aware

= Free, open source, no account =

Everything in the plugin is free. There is no paid version, no sign-up and no tracking. Development happens in the open on [GitHub](https://github.com/CptNope/PHP2Shell-WP-scanner).

= Need hands-on help? =

The plugin is made by [Jeremy Anderson](https://jeremyanderson.tech/), who builds and looks after WordPress sites. If you'd rather have someone deal with a vulnerable or hacked site for you, [book a call](https://jeremyanderson.tech/book-a-call/) or see the [services](https://jeremyanderson.tech/services/). Full documentation is on the [plugin's page](https://jeremyanderson.tech/project/php2shell-wp2shell-scanner/).

== External services ==

The plugin only contacts outside servers in the cases below. It sends no analytics or personal data, and never sends your site's files or scan results anywhere you didn't set up.

* **WordPress.org core checksums** (api.wordpress.org) — during a scan, to compare your WordPress core files with the official ones. Sends your WordPress version and locale, the same request WordPress itself makes. [Terms](https://wordpress.org/about/privacy/)
* **WordPress.org plugin checksums** (downloads.wordpress.org) — during a scan, to check that this plugin's files, and those of your other plugins from WordPress.org, haven't been tampered with. Sends only each plugin's folder name and version. Turned off with the "Core and plugin files" setting (except this plugin's own self-check). [Terms](https://wordpress.org/about/privacy/)
* **Your own fleet hub** — only if you turn on the fleet dashboard and connect a site to a hub you run. After each scan the member site sends a summary to that hub, signed with a per-site key: site name and address, verdict, WordPress, PHP and plugin versions, finding counts, and the text of serious findings (email addresses removed).
* **Slack or Discord** — only if you paste a webhook address into the fleet alert settings. The hub sends alert messages (site address and what was found) to that webhook. [Slack terms](https://slack.com/terms-of-service), [Discord terms](https://discord.com/terms)
* **Email alerts** use your site's normal WordPress mail.

== Installation ==

1. Install from Plugins → Add New Plugin (search for "JAT Shell Scanner"), or upload the zip, and activate.
2. Go to Tools → PHP2Shell Scanner and click Scan now.

On multisite, network-activate and use Network Admin → Settings → PHP2Shell Scanner.

== Frequently Asked Questions ==

= Will it change or delete my files? =

Scans never do. Only if you click a fix button does it move a file into quarantine or remove someone's admin rights — and you can undo either from the Quarantine tab. Quarantined files go into the plugin's own folder in uploads (uploads/jat-shell-scanner/), blocked from the web and renamed so they can't run.

= It says "Vulnerable — PHP needs updating". Was I hacked? =

Not necessarily. It means no signs of a break-in were found, but your server's PHP can be attacked. Send your host the ready-made message on the scanner page.

= My host says PHP is patched, but the scanner disagrees. =

Some hosts fix PHP without changing its version number. If your host confirms both CVEs are fixed, click Ignore on that finding.

= Does it send my data anywhere? =

No. See "External services" above for the only outside requests it makes.

= I installed an earlier version from GitHub. =

The GitHub edition updates itself from GitHub releases. To switch to this WordPress.org edition, deactivate and delete the GitHub copy, then install this one. Deleting a plugin removes its settings, scan history and quarantine, so restore anything you need from the Quarantine tab and note your fleet settings first.

= Where do I report a bug or a new attack indicator? =

Use the [support forum](https://wordpress.org/support/plugin/jat-shell-scanner/). Security problems in the plugin itself: please report them privately through [GitHub](https://github.com/CptNope/PHP2Shell-WP-scanner/security/advisories/new).

== Screenshots ==

1. The verdict: whether PHP and WordPress are exposed, and whether there are signs of a break-in.
2. Findings, with what each one means and what to do.
3. The fleet dashboard for many sites.
4. Quarantine: every fix can be undone.

== Changelog ==

= 1.6.0 =
* Renamed to JAT Shell Scanner (by Jeremy Anderson Tech).
* Quarantine now lives in the plugin's own folder in uploads (uploads/jat-shell-scanner/) instead of wp-content. Files quarantined by earlier GitHub builds can still be restored or deleted.
* Finds every folder through WordPress's own functions, so sites with moved content, plugin or theme folders are scanned correctly, including theme folders registered elsewhere.
* Fleet reports are checked in the REST permission check.

= 1.5.1 =
* Latest PHP2Shell intel: the Potassium (Mirai) botnet's second stage, servers and download names; webshell names and markers from PHP2Shell exploit kits; poisoned session files; Apache worker aborts; 34 more attacker addresses.
* Advice for CVE-2026-115560, a related PHP flaw with no fix yet: turn off session upload progress.

= 1.5.0 =
* Looks for backdoors in the database: code stored in settings, self-decoding scripts, invisible frames and hidden links in posts, and scheduled tasks that carry code or download scripts.
* Checks plugins from WordPress.org against their official checksums, catching a backdoor written into a real plugin's file and stray PHP files in plugin folders.
* Flags drop-ins (advanced-cache.php, object-cache.php, db.php…) changed since the attacks that don't say which plugin made them.

= 1.4.0 =
* Now available on WordPress.org. The WordPress.org edition updates through WordPress.org and checks its own files against WordPress.org's checksums.
* Links to documentation, support and the author on the Plugins screen and the scanner page.
* The update check no longer sends the site address to GitHub.

= 1.3.2 =
* Recognises the Installatron Worker (it-api.php), the temporary script IONOS and other hosts use for one-click installs.
* Hidden "data" files that can only answer 404 are no longer reported as backdoors.

The full history is in [CHANGELOG.md](https://github.com/CptNope/PHP2Shell-WP-scanner/blob/main/CHANGELOG.md).

== Upgrade Notice ==

= 1.6.0 =
New name (JAT Shell Scanner); quarantine moves into the uploads folder; better support for sites with moved folders.

= 1.5.1 =
Detects the latest PHP2Shell attack tools and the botnet they install.

= 1.5.0 =
Finds backdoors that survive deleting the webshell: in the database, inside real plugin files, and in drop-ins.

= 1.4.0 =
First WordPress.org release. Adds documentation and support links.
