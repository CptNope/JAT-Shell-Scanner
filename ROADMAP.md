# Roadmap

What's planned for JAT Shell Scanner. Ideas come from users, so if you'd like something added, [open an issue](https://github.com/CptNope/jat-shell-scanner/issues).

## Done in 1.8.0

Both items below shipped in [1.8.0](CHANGELOG.md#180--2026-11-23). Thank you to everyone who suggested them.


### A plain-language summary you can forward to your host

*Suggested by Varun Dubey ([@vapvarun.bsky.social](https://bsky.app/profile/vapvarun.bsky.social)).*

Most people who install a scanner aren’t sure what to do with the findings. Before 1.8.0 the scanner had a ready-made message for the host only when PHP needed updating (**Your host needs to update PHP → Copy message**). 1.8.0 adds a summary of the whole scan that a site owner can copy or download and send to their host or developer as it is:

- The result in one sentence (for example, *"No signs of an attack, but PHP needs updating"*).
- Each Critical and High finding in plain words: what was found, where, and what the host should do about it.
- Site address, PHP and WordPress versions, scan date and the CVE numbers, so the host doesn't have to ask.
- No file contents, passwords or personal data: only paths and short descriptions.
- A **Copy summary** button next to **Download report**, and the same text from WP-CLI (`wp jat-shell scan --format=host`).

### Say clearly when temporary protections are on but PHP is still unpatched

*Suggested by Kira AI ([@hey-kira.bsky.social](https://bsky.app/profile/hey-kira.bsky.social)).*

The scanner already checks the PHP version against the fixed releases (8.2.35, 8.3.36, 8.4.27 and 8.5.12) and reports an unpatched version as High, separately from the temporary `php.ini` protections, which it lists as Info. The gap: when a host has turned on every temporary protection, the site can look handled even though the version is still vulnerable.

- When PHP is unpatched and all the advised protections are on, add one line to the result: *"Your host has turned on the temporary protections, but PHP itself is still vulnerable. Ask them to update PHP."*
- Use the same wording in the host message and the new summary, so nobody reads the protections as the fix.
- Add a test for this case (all protections on, version unpatched, result stays Vulnerable).

## Next

### Catch a PHP update that was installed but never restarted

*Suggested by Kira AI ([@hey-kira.bsky.social](https://bsky.app/profile/hey-kira.bsky.social)).*

The scanner reads the PHP version from inside the web request (`PHP_VERSION`), so it judges the PHP that is actually serving the site, never the first `php` on the server's `PATH`. WP-CLI scans use the last snapshot taken from the website. The gap: Debian, Ubuntu and other distributions often fix PHP without changing its version number, and for those the scanner relies on the package version and build date, which it reads from files on disk. If the host installed the fixed package but didn't restart PHP-FPM (or Apache with mod_php), the running workers still use the old, vulnerable code while the files say it's fixed.

- Find out when the running PHP was started: the start time of the PHP-FPM master or Apache parent process (`/proc/self/stat` and its parent, against the boot time in `/proc/stat`).
- Compare it with when the PHP package was installed or updated (the package files' dates).
- If PHP started before the update, report it as High: *"Your host installed the PHP update, but PHP hasn't been restarted, so the site is still running the old version. Ask them to restart PHP-FPM."* The result stays Vulnerable until the restart.
- Use the same wording in the host message and the plain-language summary.
- If `/proc` can't be read (`open_basedir`, other operating systems), say the restart couldn't be checked instead of guessing.
- Add tests for each case: restarted after the update, not restarted, and unknown.

### Report WordPress core files that are missing

Found while checking a site after a host move. The core check compares each core file that exists against the WordPress.org checksums, but a core file that has been deleted is never mentioned. A missing file can break part of WordPress, and an attacker can remove a file as easily as change one.

- For every file in the checksum list that isn't on disk, report it: *"WordPress core file is missing: wp-includes/…"*, with Reinstall WordPress (Dashboard → Updates → Re-install) as the fix.
- Medium for one or a few missing files, High when many are missing or they include files WordPress loads on every page.
- Skip files WordPress itself allows to be absent (for example `wp-config-sample.php`, `readme.html`, `license.txt`), and keep the existing "couldn't get checksums" message when the list can't be fetched.
- Group long lists like modified files already are ("N more missing core files").
- Add tests: nothing missing, one missing, many missing, and an allowed-absent file.

### Recognise JAT Site Shield's own key file

Found on a site that runs both plugins. JAT Site Shield can keep its two-factor encryption key in `wp-content/jatss-key.php` (its older key file; `anshield-key.php` before the rename), and the scanner reports it as High: *"PHP doesn't normally live here."* That alarms people over a file their own security plugin created.

- Don't flag `jatss-key.php` or `anshield-key.php` when the file has Site Shield's layout: an optional `ABSPATH` guard and a single `return '<64 hex characters>';`, nothing else.
- If a file with one of those names has any other contents, keep reporting it as High, so the name can't be used to hide a backdoor.
- Show it under **Everything** as "JAT Site Shield's key file (expected)".
- Add tests: genuine key file, look-alike file with code in it, and Site Shield not installed.

Suggestions welcome in the [issues](https://github.com/CptNope/jat-shell-scanner/issues).
