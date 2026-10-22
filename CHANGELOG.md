# Changelog

## [1.0.0] — 2026-10-22

First public release.

### Detection
- WordPress version check against the wp2shell ranges (6.8.0–6.8.5, 6.9.0–6.9.4, 7.0.0–7.0.1).
- Webshell plugins: `wp2shell_<hex>`, fake CMSmap, fake WP Static Cache Helper, `gg-` REST shells, and folders hidden from the Plugins screen.
- wp-content: PHP in uploads/cache/upgrade, `.htaccess` PHP handlers in uploads, hidden PHP files, exploit zips, write-test files and staging folders.
- Webshell code signatures and published SHA1 hashes.
- Administrators and application passwords created since disclosure.
- Core file integrity against wordpress.org checksums, plus unknown PHP in core folders and the site root.
- Optional access-log scan: successful batch API hits, exploit user agents, attacker IPs, plugin uploads, user enumeration.

### Usability
- Separate **Vulnerable** result for unpatched sites with no signs of attack.
- Fewer false positives: "Silence is golden" files, cache-plugin files and site-setup admins are recognised.
- Ignore list for false positives.

### Reliability
- Resumable scans in time slices — works on hosts with short PHP time limits.
- Scheduled scans (weekly by default) with email alerts for new serious findings.
- Site Health test, admin notice, WP-CLI commands (`scan`, `status`, `ignore`).
- Updates through the WordPress Updates screen from GitHub releases.
- Multisite support; clean uninstall.
