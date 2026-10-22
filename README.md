# wp2shell Scanner for WordPress

[![CI](https://github.com/CptNope/PHP2Shell-WP-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/CptNope/PHP2Shell-WP-scanner/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/CptNope/PHP2Shell-WP-scanner)](https://github.com/CptNope/PHP2Shell-WP-scanner/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A free WordPress plugin that checks your site for signs of **wp2shell** — the attack on WordPress core disclosed on July 17, 2026 (CVE-2026-63030 + CVE-2026-60137) that lets anyone take over an unpatched site without logging in.

**It only reads. It never changes or deletes anything on your site.**

## Install (2 minutes)

1. Download **[wp2shell-scanner.zip](https://github.com/CptNope/PHP2Shell-WP-scanner/releases/latest/download/wp2shell-scanner.zip)**.
2. In WordPress go to **Plugins → Add New Plugin → Upload Plugin**, choose the zip, then **Install Now** and **Activate**.
3. Go to **Tools → wp2shell Scanner** and click **Scan now**.

On multisite, network-activate it and find it under **Network Admin → Settings → wp2shell Scanner**.

> Download the zip from **Releases**, not GitHub's green "Code → Download ZIP" button — the release zip has the right folder name and gets automatic updates.

## What the result means

| Result | Meaning | What to do |
|---|---|---|
| **No signs of wp2shell** | No known indicators found. | Keep WordPress updated. |
| **Needs review** | Minor items to confirm, e.g. a must-use plugin you may not recognise. | Look through the list; ignore anything you know is yours. |
| **Vulnerable — update WordPress** | No evidence of an attack, but your WordPress version can be hacked this way. | Update WordPress now, then scan again. |
| **Suspicious** | Something that needs a closer look today, e.g. a new admin you don't recognise. | Check each high finding. |
| **Compromised** | Strong evidence of an attack, e.g. a known webshell. | Follow the clean-up steps the plugin shows. |

Anything you know is fine can be marked **Ignore**, and it won't count towards the result or trigger alerts again.

## What it checks

- **WordPress version** — 6.9.0–6.9.4 and 7.0.0–7.0.1 (full takeover), 6.8.0–6.8.5 (database injection only). Fixed in 6.8.6, 6.9.5 and 7.0.2.
- **Plugins** — the exploit's `wp2shell_<hex>` plugins, fake "CMSmap" and "WP Static Cache Helper" plugins, `gg-` command-running plugins, and folders hidden from the Plugins screen.
- **Files in wp-content** — PHP in `uploads`, `cache` and `upgrade` folders; `.htaccess` files that switch PHP on in uploads; hidden PHP files; the exploit's leftover zips, test files and staging folders.
- **Webshell code** — request-to-`eval` one-liners (including the one that disguises itself as a 404), packed `eval(gzuncompress(base64_decode(…)))` payloads, base64 shell commands, and REST endpoints anyone can call to run commands.
- **Known webshell hashes** from published research.
- **Users** — administrators and application passwords created since July 17, 2026.
- **WordPress core files** — compared with official checksums from wordpress.org, plus unknown PHP files in `wp-admin`, `wp-includes` and the site root.
- **Access log** (optional) — successful hits on the batch API, exploit-tool user agents, known attacker IPs, plugin uploads and admin enumeration.

It's built not to cry wolf: "Silence is golden" placeholder files, cache-plugin files, and plugin/theme updates you made yourself are recognised and either skipped or marked low.

## Works on any host

- **Cheap shared hosting with short time limits?** Scans run in small slices with a progress bar, so a 30-second limit doesn't matter. Tested with 50,000+ files.
- **Automatic scans** weekly (or daily), with an **email alert** only when something new and serious turns up.
- **Site Health** shows the latest result under Tools → Site Health.
- **Automatic updates** from GitHub releases through the normal WordPress Updates screen.
- **WP-CLI** for people managing many sites (below).
- **Multisite** aware. **PHP 7.4 to 8.4**, WordPress 6.0+.
- **Uninstalling** removes everything it stored.

## WP-CLI

```bash
wp wp2shell scan                                   # table of findings
wp wp2shell scan --log=/var/log/nginx/access.log   # include the access log
wp wp2shell scan --min=high                        # only high and critical
wp wp2shell scan --format=json > report.json
wp wp2shell scan --format=summary                  # one line per site
wp wp2shell status                                 # last result, no new scan
wp wp2shell ignore <id>                            # mark a false positive (--undo to restore)
```

Exit codes: `0` clean or review · `1` vulnerable or suspicious · `2` compromised.

### Many sites at once

```bash
URL=https://github.com/CptNope/PHP2Shell-WP-scanner/releases/latest/download/wp2shell-scanner.zip

# With WP-CLI aliases (@all in wp-cli.yml)
wp @all plugin install $URL --activate
wp @all wp2shell scan --format=summary

# Or every site on one server
for d in /var/www/*/; do
  wp --path="$d" plugin install $URL --activate --force --quiet
  wp --path="$d" wp2shell scan --format=summary
done
```

## If your site is compromised

1. **Back up** files and database first — it's your evidence and your undo button.
2. **Update WordPress** to 6.8.6, 6.9.5, 7.0.2 or later.
3. **Remove** the flagged files, plugins and admin accounts.
4. **Reset** every admin password, change the database password, and replace the security keys in `wp-config.php`.
5. **Check other ways back in**: must-use plugins, `.htaccess`, scheduled tasks, server cron jobs. Then scan again.

Not comfortable doing this? Your host or a WordPress security service can clean it for you.

## Limits

Detection is based on the public exploit tools and samples. Attackers can rename files and rewrite code, so "no signs" means no *known* indicators — not a guarantee. If your site ran a vulnerable version while online, treat it as possibly compromised until you've checked.

## Privacy

Everything runs on your server. The only outside connections are the ones WordPress itself makes: core checksums from wordpress.org, and the update check to GitHub's API (twice a day at most). No data about your site is sent anywhere.

## Development

```bash
# Run the integration tests against a throwaway site (they plant fake malware files!)
tests/integration.sh /path/to/throwaway/wordpress
```

CI lints PHP 7.4–8.4 and runs the integration tests on vulnerable and current WordPress versions. To release: bump the version in `wp2shell-scanner.php` (header and `WP2SS_VERSION`) and `readme.txt`, add a `CHANGELOG.md` entry, then push a `vX.Y.Z` tag — the Release workflow builds and publishes the zip.

Detection rules live in [`includes/signatures.php`](includes/signatures.php). New indicators are very welcome — open an issue or PR with a source.

## Sources

- [Wiz Research — Exploitation in the Wild of wp2shell](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)
- [Elastic Security Labs — wp2shell detection](https://www.elastic.co/security-labs/blog/wp2shell-wordpress-rce-detection-elastic-defend)
- [MalwareBazaar — wp-static-cache sample](https://bazaar.abuse.ch/sample/4b7ff0262fe7d98cfd1c3ec38cb17d1aa7b66524be8fa2de0ce7a30a3d81fa38/)

## License

MIT — see [LICENSE](LICENSE).
