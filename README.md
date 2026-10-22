# PHP2Shell WP Scanner

A read-only WordPress plugin that checks a site for signs of **wp2shell** exploitation — the pre-auth RCE chain in WordPress core (CVE-2026-63030 + CVE-2026-60137, disclosed July 17, 2026).

It never modifies, moves or deletes anything. It reports; you decide.

## What it checks

| Area | What it looks for |
|---|---|
| Core version | 6.9.0–6.9.4 and 7.0.0–7.0.1 (full RCE), 6.8.0–6.8.5 (SQL injection only) |
| Plugins | `wp2shell_<hex>` folders, fake **CMSmap**, fake **WP Static Cache Helper**, `gg-` REST shells, folders with PHP but no plugin header, plugins installed after disclosure |
| wp-content | PHP in `uploads/`, `cache/`, `upgrade/`; `wp2shell_*.zip`; `temp-write-test-*` probes; staging folders |
| Code | `eval($_POST…)` one-liners (incl. the 404-masking variant), packed `eval(gzuncompress(base64_decode…))`, base64 command exec, public REST routes that run shell commands |
| Hashes | Published webshell SHA1s (Wiz Research, MalwareBazaar) |
| Users | Administrators / super admins created on or after 2026-07-17 |
| MU plugins | Must-use plugins changed since disclosure |
| REST | Routes registered in the `morning/v1` namespace |
| Core | Files vs. wordpress.org checksums; unknown PHP in `wp-admin`, `wp-includes`, site root |
| Access log (optional) | 200/207 hits on the batch API, `wp2shell`/`rezwp2shell` user-agents, known attacker IPs, plugin uploads, admin user enumeration |

Each run ends with a verdict: **COMPROMISED**, **SUSPICIOUS**, **REVIEW** or **CLEAN**.

## Install

Download this repo as a zip (Code → Download ZIP) and upload it under **Plugins → Add New → Upload Plugin**, or:

```bash
wp plugin install https://github.com/CptNope/PHP2Shell-WP-scanner/archive/refs/heads/main.zip --activate
```

## Use

**Dashboard:** Tools → wp2shell Scanner (Network Admin → Settings on multisite). Results can be downloaded as JSON.

**WP-CLI** (recommended for large sites — no request timeouts):

```bash
wp wp2shell scan
wp wp2shell scan --log=/var/log/nginx/access.log --min=medium
wp wp2shell scan --format=json > report.json
wp wp2shell scan --format=summary
```

| Option | Meaning |
|---|---|
| `--log=<path>` | Access log to check (`.gz` works) |
| `--skip-core` | Skip the wordpress.org checksum check |
| `--min=<level>` | `info`, `low`, `medium`, `high`, `critical` (default `low`) |
| `--format=<fmt>` | `table`, `json`, `csv`, `summary` |

Exit codes: `0` clean/review, `1` suspicious, `2` compromised — handy for scripts.

## Scanning many sites

With WP-CLI aliases (`@all` in `wp-cli.yml`):

```bash
wp @all plugin install https://github.com/CptNope/PHP2Shell-WP-scanner/archive/refs/heads/main.zip --activate
wp @all wp2shell scan --format=summary
```

Or loop over sites on one server:

```bash
for d in /var/www/*/; do
  wp --path="$d" plugin install https://github.com/CptNope/PHP2Shell-WP-scanner/archive/refs/heads/main.zip --activate --force --quiet
  wp --path="$d" wp2shell scan --format=summary
done
```

## If a site is flagged

1. Back up files and database first — that's your evidence.
2. Update WordPress to **6.8.6 / 6.9.5 / 7.0.2** or later.
3. Remove the flagged files, plugins and admin users.
4. Reset every admin password, rotate the database password and the salts in `wp-config.php`.
5. Look for other persistence: cron jobs, mu-plugins, `.htaccess`, the server crontab.

**Low** findings (e.g. theme files changed after July 17) are usually just updates — they're listed so you can confirm.

## Limits

Signatures match the public tooling and samples. Attackers can rename plugins and rewrite payloads, so a clean result means "no known indicators", not "definitely safe". If a vulnerable version was exposed to the internet, treat the site as possibly compromised until you've reviewed it.

## Sources

- [Wiz Research — Exploitation in the Wild of wp2shell](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)
- [Elastic Security Labs — wp2shell detection](https://www.elastic.co/security-labs/blog/wp2shell-wordpress-rce-detection-elastic-defend)
- [MalwareBazaar — wp-static-cache sample](https://bazaar.abuse.ch/sample/4b7ff0262fe7d98cfd1c3ec38cb17d1aa7b66524be8fa2de0ce7a30a3d81fa38/)

## License

MIT — see [LICENSE](LICENSE).
