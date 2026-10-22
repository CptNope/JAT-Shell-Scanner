=== wp2shell Scanner ===
Requires at least: 6.0
Requires PHP: 7.4
Stable tag: 1.0.0
License: MIT

Read-only scan for signs of wp2shell (CVE-2026-63030 + CVE-2026-60137) exploitation. Nothing is changed or deleted.

== What it checks ==

* Core version: 6.9.0–6.9.4 and 7.0.0–7.0.1 (full RCE), 6.8.0–6.8.5 (SQLi)
* Dropped plugins: wp2shell_<hex>, "CMSmap", fake "WP Static Cache Helper", "gg-" REST shells, folders with no plugin header
* wp-content: PHP in uploads/cache/upgrade, wp2shell_*.zip, temp-write-test-* probes, staging folders
* Webshell code: eval($_POST…), packed eval(gzuncompress(base64_decode…)), base64 command exec, open REST routes running shell commands
* Published webshell SHA1 hashes
* Administrators created on/after 2026-07-17
* Must-use plugins changed since disclosure
* Registered REST routes in the morning/v1 namespace
* Core files vs wordpress.org checksums + unknown PHP in wp-admin / wp-includes / root
* Optional access log: 200/207 batch API hits, wp2shell user-agents, known attacker IPs, plugin uploads, user enumeration

== Using it ==

Dashboard: Tools → wp2shell Scanner (Network Admin → Settings on multisite). Download results as JSON.

WP-CLI (recommended for big sites):

    wp wp2shell scan
    wp wp2shell scan --log=/var/log/nginx/access.log --min=medium
    wp wp2shell scan --format=json > report.json

Exit codes: 0 clean/review, 1 suspicious, 2 compromised.

== Sweeping many sites ==

With WP-CLI aliases (wp-cli.yml @all):

    wp @all plugin install /path/wp2shell-scanner.zip --activate
    wp @all wp2shell scan --format=summary

Or a loop on one server:

    for d in /var/www/*/; do
      wp --path="$d" plugin install /path/wp2shell-scanner.zip --activate --force --quiet
      wp --path="$d" wp2shell scan --format=summary
    done

== If a site is flagged ==

1. Back up files + database first (evidence).
2. Update WordPress to 6.8.6 / 6.9.5 / 7.0.2 or later.
3. Remove flagged files, plugins and admin users.
4. Reset all admin passwords, rotate the DB password and the salts in wp-config.php.
5. Check for other persistence: cron jobs, mu-plugins, .htaccess, server crontab.

Severity "low" items (e.g. theme files changed after July 17) are usually just updates — they're there so you can confirm.
