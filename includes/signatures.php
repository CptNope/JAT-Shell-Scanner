<?php
/**
 * Indicators for the two attacks this plugin looks for.
 *
 *  PHP2Shell — CVE-2026-109618 / CVE-2026-109619, memory-safety bugs in the PHP
 *  engine itself (disclosed 2026-10-21, exploitation seen from 2026-10-17).
 *  Fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12.
 *
 *  wp2shell — CVE-2026-63030 / CVE-2026-60137, a pre-auth RCE chain in
 *  WordPress core (disclosed 2026-07-17). Fixed in 6.8.6, 6.9.5 and 7.0.2.
 *
 * Kept separate from the scanner logic so they are easy to review and update.
 * Add your own with the `wp2ss_signatures` filter.
 *
 * Sources: php.net / GitHub php-src advisories, Wiz, Tenable, Sansec, Help Net
 * Security, Detection Opportunities gist (Blevene) for PHP2Shell; Wiz,
 * Elastic Security Labs and MalwareBazaar for wp2shell. See README.md.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return array(

	/* ------------------------------------------------------------------ */
	/* PHP2Shell (PHP engine)                                              */
	/* ------------------------------------------------------------------ */

	// Earliest exploitation seen (Amazon MadPot honeypot): 2026-10-17 00:00 UTC.
	'php2shell_ts'      => 1792195200,

	// First fixed release per branch. Branches below 8.2 got no official release.
	'php_fixed'         => array(
		'8.2' => '8.2.35',
		'8.3' => '8.3.36',
		'8.4' => '8.4.27',
		'8.5' => '8.5.12',
	),

	// Branches for which the PHP team published source-only backports.
	'php_backport_only' => array( '7.4', '8.0', '8.1' ),

	// Distribution packages that keep the old PHP version number but carry the fix:
	// [ package version prefix, first fixed revision ]. Ubuntu USN-8948-1/-2.
	'php_fixed_pkg'     => array(
		array( '8.1.2-1ubuntu2.', 28 ),
		array( '8.3.6-0ubuntu0.24.04.', 13 ),
		array( '8.5.4-0ubuntu1.', 5 ),
		array( '8.5.9-0ubuntu2.', 1 ),
	),

	// The fix was published 2026-10-21; a PHP built on or after this date may carry a backport.
	'php_fix_date'      => 1792540800,

	// PHP error-log lines that point at PHP2Shell attempts: [ key, severity, regex, description ].
	'php_error_log'     => array(
		// A request-startup out-of-memory fatal names no script ("in Unknown on line 0");
		// ordinary out-of-memory errors in WordPress name a file.
		array( 'oom_unknown', 'medium', '/Allowed memory size of \d+ bytes exhausted.*\bin (<b>)?Unknown(<\/b>)? on line (<b>)?0\b/i', 'out-of-memory errors raised before any script ran ("in Unknown on line 0")' ),
		// Also logged by the *patched* 8.4.27 / 8.5.12 (php-src #24493), so it only counts on unpatched PHP.
		array( 'session_decode', 'medium', '/Failed to decode session object/i', '"Failed to decode session object" errors' ),
		array( 'segfault', 'high', '/exited on signal 11|\bSIGSEGV\b|segfault at [0-9a-f]+ .*php|zend_mm_heap corrupted/i', 'PHP worker crashes (segmentation faults / heap corruption)' ),
	),

	// Exploit tools and payloads reported for PHP2Shell (ELLIO; Amazon): user agents, canary, download URL.
	'php2shell_log'     => '/php2shell-(scan|verify|109618)|JACKALPOC|92\.118\.112\.100|\/tmp\/nfs\b/i',

	// Addresses Amazon saw attempting PHP2Shell (anonymisation services: investigate, don't just block).
	'php2shell_ips'     => array( '103.216.220.92', '31.223.184.166', '37.19.200.5', '134.209.159.64', '103.114.163.188', '95.217.98.37' ),

	// Second-stage malware dropped in /tmp as "nfs" (ELLIO).
	'php2shell_files'   => array(
		'0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486' => 'PHP2Shell second-stage ELF (ELLIO)',
	),

	// Thresholds (count since php2shell_ts) at which an error-log pattern escalates to high.
	'php_error_burst'   => 5,

	// Access log: POSTs answered with these statuses, from one IP, at or above this count.
	'post_fail_status'  => array( '500', '502' ),
	'post_fail_burst'   => 20,

	/* ------------------------------------------------------------------ */
	/* wp2shell (WordPress core)                                           */
	/* ------------------------------------------------------------------ */

	// Public disclosure: 2026-07-17 00:00 UTC. Changes after this are worth a look.
	'disclosure_ts'     => 1784246400,

	// Affected WordPress ranges: [ min inclusive, max exclusive, severity, label, fixed in ].
	// WordPress names major releases "7.0", not "7.0.0", so lower bounds are written that way.
	'vulnerable'        => array(
		array( '6.9', '6.9.5', 'critical', 'the full wp2shell RCE chain', '6.9.5' ),
		array( '7.0', '7.0.2', 'critical', 'the full wp2shell RCE chain', '7.0.2' ),
		array( '6.8', '6.8.6', 'high', 'the wp2shell SQL injection (CVE-2026-60137)', '6.8.6' ),
	),

	// Published webshell SHA1 hashes.
	'sha1'              => array(
		'2a1410d8e2a8337ac2171cedea8c0fdc47c647a0' => 'wp2shell webshell (Wiz)',
		'58eca847e9eae9e6b08cc211f1559817b71bc4cc' => 'wp2shell webshell (Wiz)',
		'ebea44890f434d5d67ede22009a3f4bb5cac33f8' => 'wp2shell webshell (Wiz)',
		'd9a220c8039f1c4d72cae7ccb8b3a33dec8815be' => 'wp2shell webshell (Wiz)',
		'e9756e2338f84746007235e4cab7a70d5b3ca47f' => 'wp2shell webshell (Wiz)',
		'c12f2993e618a1ae1b9964876facc196221371fb' => 'wp2shell wp-static-cache webshell (MalwareBazaar)',
	),

	// wp2shell attacker infrastructure (access-log checks only).
	'ips'               => array(
		'34.81.132.62',
		'79.177.131.206',
		'15.157.135.170',
		'94.100.52.128',
		'172.235.128.52',
	),

	// wp2shell exploit-tool user agents.
	'user_agents'       => '/\b(rez)?wp2shell\b|cve-2026-63030/i',

	// REST namespaces registered by known webshell plugins.
	'rest_namespaces'   => array( 'morning/v1' ),

	/* ------------------------------------------------------------------ */
	/* Webshells in general (what either attack leaves behind)             */
	/* ------------------------------------------------------------------ */

	// Code signatures: [ severity, regex, description ]. The most severe match per file is reported.
	'code'              => array(
		array( 'critical', '/eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[[^\]]+\]\s*\?\?\s*[\'"]http_response_code\(\s*404\s*\)/i', 'Webshell one-liner that hides behind a 404 (seen with wp2shell)' ),
		array( 'critical', '/\b(eval|assert)\s*\(\s*(stripslashes\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE)\b/i', 'Executes code straight from a web request' ),
		array( 'critical', '/(?<![\w>:$])(system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*(base64_decode\s*\(\s*)?\$(_GET|_POST|_REQUEST|_COOKIE|_SERVER|request|req|r)\b/i', 'Runs shell commands taken from a web request' ),
		array( 'high', '/\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/', 'Calls a function whose name comes from a web request' ),
		array( 'high', '/\beval\s*\(\s*(gzuncompress|gzinflate|gzdecode|str_rot13)\s*\(\s*base64_decode\s*\(/i', 'Packed/obfuscated eval payload (CMSmap-style webshell)' ),
		array( 'high', '/\b(eval|assert)\s*\([^;]{0,80}base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=\s]{400,}/i', 'Evaluates a large hidden (base64) payload' ),
		array( 'high', '/\bcreate_function\s*\([^;]{0,120}\$_(POST|GET|REQUEST|COOKIE)\b/i', 'Builds a function from web-request input' ),
		array( 'high', '/\$\{\s*[\'"]_(P|G|R|C)[\'"]\s*\.\s*[\'"]/', 'Hides a $_POST/$_GET reference by splitting its name' ),
		array( 'high', '/\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)\b/i', 'Includes a file named by a web request' ),
		array( 'high', '/\b(include|require)(_once)?\s*\(?\s*[\'"][^\'"]+\.(ico|png|jpe?g|gif|webp|bmp)[\'"]/i', 'Includes an image file as PHP code' ),
		array( 'high', '/\bfile_put_contents\s*\([^;]{0,200}\$_(POST|GET|REQUEST)\b/i', 'Writes attacker-supplied content to disk' ),
		array( 'medium', '/\$[a-z_]\w*\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\)\s*;/i', 'Calls a function named by a variable with web-request input' ),
	),

	// PHP-executable extensions.
	'php_ext'           => '/\.(php\d?|phtml|pht|phar|inc)$/i',

	// Image types checked for hidden PHP when they sit in uploads.
	'image_ext'         => '/\.(jpe?g|png|gif|ico|webp|bmp)$/i',

	// Folders under wp-content that should hold data, not PHP.
	'data_dirs'         => array( 'uploads', 'cache', 'upgrade' ),

	// Legit PHP that cache and other plugins keep in data folders (path relative to wp-content).
	'data_allow'        => '#^(cache/(object|db|page_enhanced|wp-rocket|min|autoptimize|litespeed|w3tc-config|minify|busting|wpfc-minified|breeze|swift-performance|comet-cache|supercache|acorn|twig|blade|wp-cache-[^/]+\.php|meta/wp-cache-)|uploads/(sucuri|matomo|wpml/twig|wp-staging|ithemes-security|backwpup|wpo-cache|elementor/twig|siteground-optimizer-assets))#i',

	// Files that may legitimately sit directly in wp-content.
	'content_root_allow' => array( 'index.php', 'advanced-cache.php', 'object-cache.php', 'db.php', 'db-error.php', 'sunrise.php', 'maintenance.php', 'php-error.php', 'fatal-error-handler.php', 'install.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php', 'wp-cache-config.php', 'wflogs', 'debug.log' ),

	// Upload-folder .htaccess lines that make PHP executable (Wordfence's protective "AddHandler cgi-script .php" is fine).
	'htaccess_php'      => '/^\s*(?:(?:AddHandler|SetHandler)\s+\S*(?:x-httpd-\S*php|php\d*-script|lsphp|php\d*-cgi|application\/x-httpd-php)|AddType\s+application\/x-httpd-php|php_flag\s+engine\s+on)/im',

	// PHP settings that load a file into every request.
	'auto_prepend'      => '/^\s*(?:php_value\s+)?(auto_prepend_file|auto_append_file)\s*[= ]\s*["\']?([^"\'\s]+)/im',
	'auto_prepend_allow' => '#(wordfence-waf\.php|/wp-content/plugins/[^/]+/|/wflogs/|ninjafirewall|malcare|bitninja|imunify|/usr/share/)#i',

	// Must-use plugins that hosts install and update themselves.
	'host_mu_plugins'   => '/^(mu-plugin|wpengine-common|wpe-|slt-force-strong|force-strong-passwords|kinsta-mu-plugins|gd-system-plugin|sso|endurance-|bluehost|wpcomsh|wpcom|pantheon|object-cache|redis-cache|batcache|wp-cache-memcached|siteground|sg-|hostinger|flywheel|wpaas|pressable|nexcess|cloudways|breeze|godaddy|onecom|dreamhost|ionos|liquidweb)[\w.-]*\.php$/i',

	// Non-core PHP commonly found in the site root.
	'root_allow'        => array( 'wordfence-waf.php', 'wp-config.php', 'wp-cli.php', 'local-config.php', 'wp-config-local.php' ),

	// Capabilities that only administrators should have.
	'admin_caps'        => array( 'install_plugins', 'edit_plugins', 'activate_plugins', 'edit_users', 'promote_users', 'create_users', 'unfiltered_upload', 'edit_files', 'update_core' ),
);
