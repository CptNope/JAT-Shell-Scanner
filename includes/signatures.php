<?php
/**
 * Indicators of compromise for wp2shell (CVE-2026-63030 / CVE-2026-60137).
 *
 * Kept separate from the scanner logic so they are easy to review and update.
 * Sources:
 *  - Wiz Research, "Exploitation in the Wild of wp2shell" (2026-07-20)
 *  - Elastic Security Labs, wp2shell detection write-up (2026-07-23)
 *  - MalwareBazaar sample 4b7ff026… (wp-static-cache-*.php)
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return array(

	// Public disclosure: 2026-07-17 00:00 UTC. Changes after this are worth a look.
	'disclosure_ts' => 1784246400,

	// Affected WordPress core ranges: [ min inclusive, max exclusive, severity, label ].
	'vulnerable'    => array(
		array( '6.9.0', '6.9.5', 'critical', 'the full wp2shell RCE chain', '6.9.5' ),
		array( '7.0.0', '7.0.2', 'critical', 'the full wp2shell RCE chain', '7.0.2' ),
		array( '6.8.0', '6.8.6', 'high', 'the wp2shell SQL injection (CVE-2026-60137)', '6.8.6' ),
	),

	// Published webshell SHA1 hashes.
	'sha1'          => array(
		'2a1410d8e2a8337ac2171cedea8c0fdc47c647a0' => 'Wiz IOC',
		'58eca847e9eae9e6b08cc211f1559817b71bc4cc' => 'Wiz IOC',
		'ebea44890f434d5d67ede22009a3f4bb5cac33f8' => 'Wiz IOC',
		'd9a220c8039f1c4d72cae7ccb8b3a33dec8815be' => 'Wiz IOC',
		'e9756e2338f84746007235e4cab7a70d5b3ca47f' => 'Wiz IOC',
		'c12f2993e618a1ae1b9964876facc196221371fb' => 'MalwareBazaar wp-static-cache sample',
	),

	// Attacker infrastructure (for access-log checks only).
	'ips'           => array(
		'34.81.132.62',
		'79.177.131.206',
		'15.157.135.170',
		'94.100.52.128',
		'172.235.128.52',
	),

	// Exploit tool user-agents.
	'user_agents'   => '/\b(rez)?wp2shell\b|cve-2026-63030/i',

	// REST namespaces registered by known webshell plugins.
	'rest_namespaces' => array( 'morning/v1' ),

	// Code signatures: [ severity, regex, description ]. First match per file wins.
	'code'          => array(
		array( 'critical', '/eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[[^\]]+\]\s*\?\?\s*[\'"]http_response_code\(\s*404\s*\)/i', 'Webshell one-liner that hides behind a 404 (seen with wp2shell)' ),
		array( 'critical', '/\b(eval|assert)\s*\(\s*(stripslashes\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE)\b/i', 'Executes code straight from a web request' ),
		array( 'critical', '/\b(passthru|shell_exec|system|exec|popen|proc_open)\s*\(\s*base64_decode\s*\(\s*\$(request|req|r|_POST|_GET|_REQUEST)\b/i', 'Runs base64-encoded shell commands from a request' ),
		array( 'high', '/\beval\s*\(\s*(gzuncompress|gzinflate|gzdecode|str_rot13)\s*\(\s*base64_decode\s*\(/i', 'Packed/obfuscated eval payload (CMSmap-style webshell)' ),
		array( 'high', '/\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)\b/i', 'Includes a file named by a web request' ),
		array( 'high', '/\bfile_put_contents\s*\([^;]{0,200}\$_(POST|GET|REQUEST)\b/i', 'Writes attacker-supplied content to disk' ),
	),

	// PHP-executable extensions.
	'php_ext'       => '/\.(php\d?|phtml|pht|phar|inc)$/i',

	// Folders under wp-content that should hold data, not PHP.
	'data_dirs'     => array( 'uploads', 'cache', 'upgrade', 'upgrade-temp-backup' ),

	// Legit PHP that cache plugins keep under wp-content/cache/.
	'cache_engines' => '#^cache/(object|db|page_enhanced|wp-rocket|min|autoptimize|litespeed|w3tc-config|minify|busting|wpfc-minified|breeze|swift-performance|comet-cache)/#i',

	// Non-core PHP commonly found in the site root.
	'root_allow'    => array( 'wordfence-waf.php', 'wp-config.php', 'wp-cli.php', 'local-config.php', 'wp-config-local.php' ),
);
