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

Nothing scheduled yet. Suggestions welcome in the [issues](https://github.com/CptNope/jat-shell-scanner/issues).
