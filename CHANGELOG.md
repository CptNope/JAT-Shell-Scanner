# Changelog

## [1.2.0] — 2026-10-22

### One-click fixes (optional, undoable)
- **Quarantine file / Quarantine plugin** buttons move flagged files and plugin folders into a private, locked quarantine folder where they can't run. **Remove admin rights** turns an unknown administrator into a Subscriber, revokes Super Admin and logs them out.
- **Quarantine them all** for every critical/high file finding at once.
- New **Quarantine** tab with **Restore**, **Undo** and **Delete**. Fix records are signed, so they can't be forged to move files elsewhere.
- Refuses core folders, `wp-config.php`, the main `wp-content` folders, whole themes and the scanner itself; respects `DISALLOW_FILE_MODS`. Scans themselves still never change anything.
- WP-CLI: `wp php2shell fix`, `wp php2shell quarantine list|restore|delete`.

### Fleet dashboard
- Make one site the **hub**; others report their verdict, versions, counts and serious findings to it after every scan (HMAC-signed, timestamped, sanitised; off by default).
- Hub **Fleet** tab: every site worst-first, stale sites marked, CSV export, key rotation.
- WP-CLI: `wp php2shell fleet hub|join|leave|send|status|list`.

### Latest PHP2Shell intel
- Reads the installed **Debian/Ubuntu PHP package version** and knows the first fixed Ubuntu builds (22.04, 24.04, 25.10, 26.04), so "same version number, patched package" is settled automatically.
- PHP built after October 21, 2026 is reported as "probably patched".
- Access-log detection of the public exploit and scanner tools (`php2shell-scan`, `php2shell-verify`, `JACKALPOC`), their payload server, and addresses reported attacking PHP2Shell.
- Looks for the reported `/tmp/nfs` second stage, with a known malware hash.
- "Failed to decode session object" is informational on patched 8.4.27/8.5.12, which log it more often (php-src #24493).
- Temporary php.ini protections are now described as partial, with `post_max_size` and `max_input_nesting_level` added; the host message includes the package version.
- Docs: no longer tie memory leaks to one CVE — 109618 is out-of-memory corruption, 109619 is stale request state; either can lead to a leak or code execution.

### Redesigned scanner page
- A one-sentence verdict with three panels (PHP2Shell, wp2shell, signs of a break-in) and a personal "What to do next" list.
- Findings grouped by area with Needs action / Everything / Ignored filters; tabs for Findings, Quarantine, Fleet and Settings.
- Accessible: keyboard focus, reduced motion, works on phones.

## [1.1.0] — 2026-10-22

Now covers **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619), the critical PHP engine vulnerabilities disclosed on October 21, 2026, alongside wp2shell. Renamed to **PHP2Shell & wp2shell Scanner** (the plugin folder, update channel and `wp wp2shell` command are unchanged).

### PHP2Shell
- Checks the PHP your **website** runs (recorded from the dashboard, so WP-CLI scans judge the right PHP) against the fixed releases 8.2.35, 8.3.36, 8.4.27 and 8.5.12; flags source-backport-only branches (7.4–8.1) and branches that will never be fixed.
- Recognises OS-packaged PHP (Ubuntu, Debian, RHEL family, CloudLinux…) that may be patched without a version change, and says "ask your host" instead of "vulnerable".
- Reports the temporary php.ini protections (`session.upload_progress.enabled`, `memory_limit`, `fatal_error_backtraces`) and flags Apache mod_php as highest risk.
- Remembers PHP version history and warns if the site ran an unpatched PHP after October 17, 2026, with advice to rotate secrets.
- Reads the PHP error log and `debug.log` for "Allowed memory size … in Unknown on line 0", "Failed to decode session object" and worker crashes since October 17; flags out-of-memory errors that shouldn't be possible with `memory_limit=-1`.
- Spots bursts of POSTs answered with 500/502 from one address in the access log.
- New **"Your host needs to update PHP"** box with a ready-to-send support message.
- New verdict wording: "Vulnerable — PHP needs updating" / "update WordPress" / both.

### New checks
- Webshells across the whole site: `system($_GET…)`, `$_GET['f'](…)`, images included as PHP, large base64 payloads, split `$_POST` names, `create_function`; REST shells with any permission callback.
- PHP hidden inside uploaded images; PHP loose in `wp-content`; hidden PHP in the site root; `auto_prepend_file`/`auto_append_file` in `.user.ini`/`.htaccess`; code in `wp-config.php`.
- Existing or backdated accounts that became administrators since the previous scan (signed baseline); non-admin roles given admin powers.
- Plugin and upload folders outside `wp-content`; symlinked folders.
- Self-integrity: every file of this plugin is checked against the release's SHA-256 manifest published on GitHub.

### Fixes (from an independent review)
- WordPress "7.0", "6.9", "6.8" (no `.0` suffix) were not recognised as vulnerable.
- The official Performance Lab plugin was flagged as a critical webshell.
- Wordfence's protective uploads `.htaccess` and WordPress's `upgrade-temp-backup` folder were flagged.
- A file name that isn't valid UTF-8 could stall a scan forever.
- Multisite scheduled a separate scan for every subsite.
- Dismissing the admin notice didn't stick.
- PHP warnings printed by a host could break the progress bar.
- Ignored findings came back when a date or count in them changed; log-count findings re-sent alert emails every week.
- URL-encoded batch-API requests were missed in access logs.

### Robustness
- Scan state is depth-first with one open folder per level: tiny saved state, resumable mid-folder, no re-reading huge folders.
- Database lock so two tabs or a tab plus a scheduled scan can't trample each other; cancelled scans stay cancelled.
- Steps that can hang (e.g. fetching checksums from a host that drops connections) are tried at most twice.
- Checks that throw are reported and the rest of the scan continues.
- Scheduled scans use the whole cron request and survive long pauses on quiet sites (abandoned only after 24 h without progress).
- Ignore list signed with `wp-config.php` secrets; an ignored file that changes is flagged again.
- Files over 5 MB: first and last 1 MB checked. Each file is read once.
- Alert emails forced to plain text. `Update URI` header so no other plugin can hijack updates. Site Health warns when the last clean scan is stale.
- Requires PHP 7.0+ (was 7.4) so older, most-at-risk servers can run it.

### Tooling
- CI: PHP 7.0–8.5 lint; integration tests on WP latest/7.0/7.0.1/6.9.4/6.4 with ~90 checks; false-positive run over WordPress core and six popular plugins (16,000+ files); README diagram validation. Actions pinned to commit SHAs.
- Releases publish `manifest.json` and a SHA-256 checksum alongside the zip.
- Translation template in `languages/`.

## [1.0.0] — 2026-10-22

First public release (wp2shell only).
