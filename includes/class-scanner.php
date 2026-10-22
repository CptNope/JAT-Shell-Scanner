<?php
/**
 * Core scanner. Read-only: never modifies, moves or deletes anything.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2Shell_Scanner {

	/** Public disclosure date of wp2shell. Anything new after this is worth a look. */
	const DISCLOSURE_TS = 1784246400; // 2026-07-17 00:00:00 UTC.

	/** Max file size (bytes) to read for content signatures. */
	const MAX_READ = 5242880; // 5 MB.

	/** Published webshell SHA1s (Wiz Research, July 2026). */
	private static $bad_sha1 = array(
		'2a1410d8e2a8337ac2171cedea8c0fdc47c647a0',
		'58eca847e9eae9e6b08cc211f1559817b71bc4cc',
		'ebea44890f434d5d67ede22009a3f4bb5cac33f8',
		'd9a220c8039f1c4d72cae7ccb8b3a33dec8815be',
		'e9756e2338f84746007235e4cab7a70d5b3ca47f',
		'c12f2993e618a1ae1b9964876facc196221371fb', // wp-static-cache-*.php (MalwareBazaar).
	);

	/** Exploitation source IPs (Wiz Research). Used only for the optional log scan. */
	private static $bad_ips = array(
		'34.81.132.62',
		'79.177.131.206',
		'15.157.135.170',
		'94.100.52.128',
		'172.235.128.52',
	);

	/** @var array Findings collected during a run. */
	private $findings = array();

	/** @var array Stats. */
	private $stats = array(
		'files_scanned' => 0,
		'started'       => 0,
		'duration'      => 0,
	);

	/** @var string Absolute path of this plugin, excluded from content scans. */
	private $self_dir;

	public function __construct() {
		$this->self_dir = wp_normalize_path( dirname( __DIR__ ) );
	}

	/**
	 * Run every check.
	 *
	 * @param array $args { @type string $log Optional access log path. @type bool $core Verify core checksums. }
	 * @return array Report.
	 */
	public function run( $args = array() ) {
		$args = wp_parse_args( $args, array( 'log' => '', 'core' => true ) );

		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore
		}
		$this->stats['started'] = microtime( true );

		$this->check_version();
		$this->check_plugins();
		$this->check_mu_plugins();
		$this->check_wp_content_files();
		$this->check_admins();
		$this->check_rest_routes();
		if ( $args['core'] ) {
			$this->check_core_checksums();
		}
		if ( ! empty( $args['log'] ) ) {
			$this->check_access_log( $args['log'] );
		}

		$this->stats['duration'] = round( microtime( true ) - $this->stats['started'], 2 );

		usort(
			$this->findings,
			function ( $a, $b ) {
				return self::sev_rank( $b['severity'] ) - self::sev_rank( $a['severity'] );
			}
		);

		return array(
			'site'      => home_url(),
			'wp'        => get_bloginfo( 'version' ),
			'scanned'   => gmdate( 'c' ),
			'stats'     => $this->stats,
			'verdict'   => $this->verdict(),
			'findings'  => $this->findings,
		);
	}

	/* ------------------------------------------------------------------ */
	/* Checks                                                              */
	/* ------------------------------------------------------------------ */

	/** 1. Is this WordPress version in the vulnerable ranges? */
	private function check_version() {
		$v = get_bloginfo( 'version' );

		if ( ( version_compare( $v, '6.9.0', '>=' ) && version_compare( $v, '6.9.5', '<' ) )
			|| ( version_compare( $v, '7.0.0', '>=' ) && version_compare( $v, '7.0.2', '<' ) ) ) {
			$this->add( 'critical', 'version', "WordPress $v is vulnerable to the full wp2shell RCE chain.", 'Update to 6.9.5 / 7.0.2 or later immediately, then treat the site as possibly compromised.' );
		} elseif ( version_compare( $v, '6.8.0', '>=' ) && version_compare( $v, '6.8.6', '<' ) ) {
			$this->add( 'high', 'version', "WordPress $v is vulnerable to the wp2shell SQL injection (CVE-2026-60137).", 'Update to 6.8.6 or later.' );
		} else {
			$this->add( 'info', 'version', "WordPress $v is not in a vulnerable range.", 'It may still have been compromised before it was patched — review the other findings.' );
		}
	}

	/** 2. Installed plugins: known-bad names, headers and recent installs. */
	private function check_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = get_plugins();
		$dir     = wp_normalize_path( WP_PLUGIN_DIR );

		foreach ( $plugins as $file => $data ) {
			$slug  = dirname( $file );
			$name  = isset( $data['Name'] ) ? $data['Name'] : '';
			$auth  = isset( $data['Author'] ) ? $data['Author'] : '';
			$where = "$dir/$file";

			if ( wp_normalize_path( "$dir/$slug" ) === $this->self_dir ) {
				continue; // This scanner.
			}

			if ( preg_match( '/^wp2shell_[0-9a-f]+$/i', $slug ) || preg_match( '/(^|\/)wp2shell_[0-9a-f]+\.php$/i', $file ) ) {
				$this->add( 'critical', 'plugin', "Plugin folder matches the wp2shell PoC naming: $slug", 'Webshell dropped by the public exploit. Deactivate, preserve a copy for evidence, remove.', $where );
			}
			if ( strcasecmp( trim( $name ), 'CMSmap' ) === 0 || stripos( $slug, 'cmsmap' ) !== false ) {
				$this->add( 'critical', 'plugin', 'Plugin named "CMSmap" installed.', 'Seen in the wild as a 150KB webshell disguised as this security tool.', $where );
			}
			if ( stripos( $name, 'WP Static Cache Helper' ) !== false || stripos( $auth, 'WordPress Performance Team' ) !== false || preg_match( '/wp-static-cache-[0-9a-f]+\.php$/i', $file ) ) {
				$this->add( 'critical', 'plugin', "Fake \"WP Static Cache Helper\" plugin: $file", 'Known wp2shell webshell disguise.', $where );
			}
			if ( preg_match( '/^gg-/i', $name ) || preg_match( '/^gg-/i', $slug ) ) {
				$this->add( 'high', 'plugin', "Plugin with \"gg-\" prefix: $name ($slug)", 'Matches a REST-API command-execution webshell seen in the wild. Inspect it.', $where );
			}

			// Single-file plugin with no folder sitting directly in /plugins is unusual.
			if ( '.' === $slug && 'hello.php' !== $file ) {
				$this->add( 'low', 'plugin', "Loose single-file plugin: $file", 'Not necessarily bad, but a common webshell pattern. Confirm you installed it.', $where );
			}

			$path  = '.' === $slug ? $where : "$dir/$slug";
			$mtime = @filemtime( $path );
			if ( $mtime && $mtime >= self::DISCLOSURE_TS ) {
				$this->add( 'medium', 'plugin', sprintf( 'Plugin "%s" installed/changed %s (after wp2shell disclosure).', $name ? $name : $slug, gmdate( 'Y-m-d H:i', $mtime ) ), 'Confirm this install or update was yours.', $path );
			}
		}

		// Folders in /plugins that WordPress doesn't list (no valid header) are suspicious.
		foreach ( (array) glob( $dir . '/*', GLOB_ONLYDIR ) as $folder ) {
			$base   = basename( $folder );
			$listed = false;
			foreach ( array_keys( $plugins ) as $file ) {
				if ( strpos( $file, $base . '/' ) === 0 ) {
					$listed = true;
					break;
				}
			}
			if ( ! $listed && glob( $folder . '/*.php' ) ) {
				$this->add( 'medium', 'plugin', "Folder with PHP but no plugin header: $base", 'Hidden from the Plugins screen. Inspect it.', wp_normalize_path( $folder ) );
			}
		}
	}

	/** 3. Must-use plugins load silently and are a favourite persistence spot. */
	private function check_mu_plugins() {
		if ( ! defined( 'WPMU_PLUGIN_DIR' ) || ! is_dir( WPMU_PLUGIN_DIR ) ) {
			return;
		}
		foreach ( (array) glob( WPMU_PLUGIN_DIR . '/*.php' ) as $f ) {
			$m = @filemtime( $f );
			if ( $m && $m >= self::DISCLOSURE_TS ) {
				$this->add( 'medium', 'mu-plugin', 'Must-use plugin added/changed ' . gmdate( 'Y-m-d H:i', $m ) . ': ' . basename( $f ), 'MU plugins run on every request and don’t show as normal plugins. Confirm it’s yours.', wp_normalize_path( $f ) );
			}
		}
	}

	/** 4. Walk wp-content: hashes, code signatures, PHP in data folders, staging leftovers. */
	private function check_wp_content_files() {
		$root = wp_normalize_path( WP_CONTENT_DIR );
		if ( ! is_dir( $root ) ) {
			return;
		}

		$data_dirs     = array( '/uploads/', '/cache/', '/upgrade/', '/upgrade-temp-backup/' );
		$theme_changes = array();

		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST,
			RecursiveIteratorIterator::CATCH_GET_CHILD
		);

		foreach ( $it as $file ) {
			$path = wp_normalize_path( $file->getPathname() );
			$rel  = substr( $path, strlen( $root ) );
			$base = $file->getFilename();

			if ( strpos( $path, $this->self_dir . '/' ) === 0 ) {
				continue;
			}

			if ( $file->isDir() ) {
				if ( preg_match( '/^wp2shell_[0-9a-f]+$/i', $base ) && strpos( $rel, '/plugins/' ) !== 0 ) {
					$this->add( 'critical', 'file', "wp2shell staging folder: wp-content$rel", 'Left over from the exploit’s plugin upload.', $path );
				}
				continue;
			}

			if ( stripos( $base, 'temp-write-test-' ) === 0 ) {
				$this->add( 'high', 'file', "Write-probe file: wp-content$rel", 'The wp2shell PoC creates these to test write access.', $path );
			}
			if ( preg_match( '/^wp2shell_[0-9a-f]+\.zip$/i', $base ) ) {
				$this->add( 'critical', 'file', "wp2shell plugin archive: wp-content$rel", 'Uploaded exploit payload.', $path );
			}

			if ( ! preg_match( '/\.(php\d?|phtml|phar|inc)$/i', $base ) ) {
				continue;
			}
			$this->stats['files_scanned']++;

			// PHP where only data should live.
			foreach ( $data_dirs as $d ) {
				if ( strpos( $rel, $d ) === 0 ) {
					$is_cache_engine = ( '/cache/' === $d && $this->looks_like_cache_engine( $rel ) );
					$this->add(
						$is_cache_engine ? 'low' : 'high',
						'file',
						"PHP file in a data folder: wp-content$rel",
						'/cache/' === $d ? 'SANS ISC saw wp2shell drop webshells into wp-content/cache/ via SQL INTO OUTFILE.' : 'PHP shouldn’t live here. Inspect it.',
						$path
					);
					break;
				}
			}

			$size = $file->getSize();
			$sha1 = @sha1_file( $path );
			if ( $sha1 && in_array( $sha1, self::$bad_sha1, true ) ) {
				$this->add( 'critical', 'hash', "Known wp2shell webshell (hash match): wp-content$rel", "SHA1 $sha1 is a published IOC.", $path );
				continue;
			}

			if ( $size > 0 && $size <= self::MAX_READ ) {
				$this->scan_contents( $path, $rel, $size );
			}

			$m = $file->getMTime();
			if ( $m >= self::DISCLOSURE_TS && preg_match( '#^/themes/([^/]+)/#', $rel, $tm ) ) {
				$theme_changes[ $tm[1] ][] = $rel;
			}
		}

		foreach ( $theme_changes as $theme => $files ) {
			$this->add( 'low', 'file', sprintf( 'Theme "%s": %d PHP file(s) changed since wp2shell disclosure.', $theme, count( $files ) ), 'Normal after a theme update. If you didn’t update it, inspect: ' . implode( ', ', array_slice( $files, 0, 5 ) ) . ( count( $files ) > 5 ? ' …' : '' ), wp_normalize_path( WP_CONTENT_DIR . '/themes/' . $theme ) );
		}
	}

	/** Content signatures. Kept tight to limit false positives. */
	private function scan_contents( $path, $rel, $size ) {
		$code = @file_get_contents( $path ); // phpcs:ignore
		if ( false === $code ) {
			return;
		}

		$sigs = array(
			// Wiz one-liner: eval($_POST['x'] ?? 'http_response_code(404);')
			array( 'critical', '/eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[[^\]]+\]\s*\?\?\s*[\'"]http_response_code\(404\)/i', 'Webshell one-liner that hides behind a 404 (seen with wp2shell).' ),
			// Generic request-to-eval.
			array( 'critical', '/\b(eval|assert)\s*\(\s*(stripslashes\s*\()?\s*\$_(POST|GET|REQUEST|COOKIE)\b/i', 'Executes code straight from a web request.' ),
			// Packed payload.
			array( 'high', '/eval\s*\(\s*(gzuncompress|gzinflate|str_rot13|gzdecode)\s*\(\s*base64_decode\s*\(/i', 'Packed/obfuscated eval payload (CMSmap-style webshell).' ),
			// Command exec of base64 from a request param.
			array( 'critical', '/(passthru|shell_exec|system|exec|popen|proc_open)\s*\(\s*base64_decode\s*\(\s*\$(request|_POST|_GET|_REQUEST)/i', 'Runs base64-encoded shell commands from a request.' ),
			// File writer one-liner.
			array( 'high', '/file_put_contents\s*\([^;]{0,200}\$_(POST|GET|REQUEST)\b/i', 'Writes attacker-supplied content to disk.' ),
		);

		foreach ( $sigs as $s ) {
			if ( preg_match( $s[1], $code ) ) {
				$this->add( $s[0], 'code', $s[2] . " — wp-content$rel", 'Open the file and confirm. If malicious: take a backup for evidence, then remove it and rotate credentials.', $path );
				return; // One code finding per file is enough.
			}
		}

		// Open REST route that executes commands (the "morning/v1" style shell).
		if ( preg_match( '/register_rest_route\s*\(/i', $code )
			&& preg_match( '/permission_callback[\'"]?\s*=>\s*[\'"]__return_true[\'"]/i', $code )
			&& preg_match( '/\b(passthru|shell_exec|system|proc_open|popen)\s*\(/i', $code ) ) {
			$this->add( 'critical', 'code', "Public REST endpoint that runs shell commands — wp-content$rel", 'Matches the REST-API webshell seen after wp2shell exploitation.', $path );
		}
	}

	/** 5. Administrator accounts created since disclosure. */
	private function check_admins() {
		$admins = get_users(
			array(
				'role__in' => array( 'administrator' ),
				'fields'   => array( 'ID', 'user_login', 'user_email', 'user_registered' ),
				'blog_id'  => get_current_blog_id(),
			)
		);
		$since = gmdate( 'Y-m-d H:i:s', self::DISCLOSURE_TS );
		foreach ( $admins as $u ) {
			if ( $u->user_registered >= $since ) {
				$this->add( 'high', 'user', sprintf( 'Administrator "%s" (%s) created %s.', $u->user_login, $u->user_email, $u->user_registered ), 'wp2shell creates rogue admins. If you don’t recognise this account, remove it and reset all admin passwords.', 'user:' . $u->ID );
			}
		}
		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$u = get_user_by( 'login', $login );
				if ( $u && $u->user_registered >= $since ) {
					$this->add( 'high', 'user', "Super admin \"$login\" created {$u->user_registered}.", 'Confirm this account is legitimate.', 'user:' . $u->ID );
				}
			}
		}
	}

	/** 6. Registered REST routes that look like shells. */
	private function check_rest_routes() {
		if ( ! function_exists( 'rest_get_server' ) ) {
			return;
		}
		$routes = array_keys( rest_get_server()->get_routes() );
		foreach ( $routes as $r ) {
			if ( preg_match( '#^/morning/v1#i', $r ) ) {
				$this->add( 'critical', 'rest', "Suspicious REST route registered: $r", 'Namespace used by a known wp2shell webshell plugin.', 'route:' . $r );
				break;
			}
		}
	}

	/** 7. Core file integrity against wordpress.org checksums. */
	private function check_core_checksums() {
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$v        = get_bloginfo( 'version' );
		$locale   = get_locale();
		$checksum = get_core_checksums( $v, $locale ? $locale : 'en_US' );
		if ( ! $checksum ) {
			$checksum = get_core_checksums( $v, 'en_US' );
		}
		if ( ! is_array( $checksum ) ) {
			$this->add( 'info', 'core', 'Couldn’t fetch core checksums from wordpress.org.', 'Run `wp core verify-checksums` manually.' );
			return;
		}
		$bad = 0;
		foreach ( $checksum as $file => $md5 ) {
			if ( strpos( $file, 'wp-content/' ) === 0 ) {
				continue;
			}
			$p = ABSPATH . $file;
			if ( file_exists( $p ) && md5_file( $p ) !== $md5 ) {
				$bad++;
				if ( $bad <= 25 ) {
					$this->add( 'high', 'core', "Modified core file: $file", 'Core files shouldn’t change. Reinstall core (`wp core download --force --skip-content`) after preserving evidence.', wp_normalize_path( $p ) );
				}
			}
		}
		if ( $bad > 25 ) {
			$this->add( 'high', 'core', ( $bad - 25 ) . ' more modified core files not listed.', 'Reinstall WordPress core.' );
		}

		// Extra PHP files in wp-admin / wp-includes that aren't part of core.
		foreach ( array( 'wp-admin', 'wp-includes' ) as $d ) {
			$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( ABSPATH . $d, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD );
			foreach ( $it as $f ) {
				if ( ! preg_match( '/\.php$/i', $f->getFilename() ) ) {
					continue;
				}
				$rel = ltrim( substr( wp_normalize_path( $f->getPathname() ), strlen( wp_normalize_path( ABSPATH ) ) ), '/' );
				if ( ! isset( $checksum[ $rel ] ) ) {
					$this->add( 'high', 'core', "Unknown PHP file in core folder: $rel", 'Not part of WordPress. Very likely a backdoor.', wp_normalize_path( $f->getPathname() ) );
				}
			}
		}
		// Unknown PHP in the web root.
		foreach ( (array) glob( ABSPATH . '*.php' ) as $f ) {
			$rel = basename( $f );
			if ( ! isset( $checksum[ $rel ] ) && 'wp-config.php' !== $rel ) {
				$this->add( 'medium', 'core', "Unknown PHP file in site root: $rel", 'Confirm you put it there.', wp_normalize_path( $f ) );
			}
		}
	}

	/** 8. Optional: grep an access log for exploitation markers. */
	private function check_access_log( $log ) {
		if ( ! is_readable( $log ) ) {
			$this->add( 'info', 'log', "Access log not readable: $log", 'Check the path and permissions.' );
			return;
		}
		$fh = preg_match( '/\.gz$/', $log ) ? @gzopen( $log, 'r' ) : @fopen( $log, 'r' );
		if ( ! $fh ) {
			return;
		}
		$counts = array( 'batch_ok' => 0, 'ua' => 0, 'ip' => 0, 'upload' => 0, 'users' => 0 );
		$sample = array();
		$read   = preg_match( '/\.gz$/', $log ) ? 'gzgets' : 'fgets';
		while ( ( $line = $read( $fh ) ) !== false ) {
			$hit = false;
			if ( preg_match( '#(rest_route=/?batch/v1|/wp-json/batch/v1)#i', $line ) && preg_match( '#"\s(200|207)\s#', $line ) ) {
				$counts['batch_ok']++;
				$hit = true;
			}
			if ( preg_match( '/(rez)?wp2shell|cve-2026-63030/i', $line ) ) {
				$counts['ua']++;
				$hit = true;
			}
			foreach ( self::$bad_ips as $ip ) {
				if ( strpos( $line, $ip ) === 0 || strpos( $line, " $ip " ) !== false ) {
					$counts['ip']++;
					$hit = true;
					break;
				}
			}
			if ( strpos( $line, 'action=upload-plugin' ) !== false ) {
				$counts['upload']++;
			}
			if ( strpos( $line, 'wp/v2/users?context=edit' ) !== false ) {
				$counts['users']++;
			}
			if ( $hit && count( $sample ) < 5 ) {
				$sample[] = trim( substr( $line, 0, 300 ) );
			}
		}
		$read === 'gzgets' ? gzclose( $fh ) : fclose( $fh );

		if ( $counts['batch_ok'] ) {
			$this->add( 'critical', 'log', "{$counts['batch_ok']} successful (200/207) batch API requests.", 'High-fidelity sign of exploitation per Wiz/Hexastrike. Samples: ' . implode( ' | ', $sample ), $log );
		}
		if ( $counts['ua'] ) {
			$this->add( 'high', 'log', "{$counts['ua']} requests with wp2shell tool user-agents.", 'Exploit tooling hit this site.', $log );
		}
		if ( $counts['ip'] ) {
			$this->add( 'high', 'log', "{$counts['ip']} requests from published wp2shell attacker IPs.", '', $log );
		}
		if ( $counts['upload'] ) {
			$this->add( 'medium', 'log', "{$counts['upload']} plugin-upload requests.", 'Match these against your own activity.', $log );
		}
		if ( $counts['users'] ) {
			$this->add( 'medium', 'log', "{$counts['users']} admin user-enumeration requests (users?context=edit).", 'Seen as wp2shell post-exploitation.', $log );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	private function looks_like_cache_engine( $rel ) {
		// Common, legitimate PHP in /cache/ (W3TC, WP Rocket, LiteSpeed, Autoptimize configs, etc).
		return (bool) preg_match( '#^/cache/(object|db|page_enhanced|wp-rocket|min|autoptimize|litespeed|w3tc-config|minify|busting)/#i', $rel )
			|| (bool) preg_match( '#/index\.php$#', $rel ) && filesize( WP_CONTENT_DIR . $rel ) < 200;
	}

	private function add( $severity, $type, $message, $advice = '', $location = '' ) {
		$this->findings[] = compact( 'severity', 'type', 'message', 'advice', 'location' );
	}

	public static function sev_rank( $s ) {
		$map = array( 'critical' => 5, 'high' => 4, 'medium' => 3, 'low' => 2, 'info' => 1 );
		return isset( $map[ $s ] ) ? $map[ $s ] : 0;
	}

	private function verdict() {
		$top = 0;
		foreach ( $this->findings as $f ) {
			$top = max( $top, self::sev_rank( $f['severity'] ) );
		}
		if ( $top >= 5 ) {
			return 'COMPROMISED';
		}
		if ( $top >= 4 ) {
			return 'SUSPICIOUS';
		}
		if ( $top >= 3 ) {
			return 'REVIEW';
		}
		return 'CLEAN';
	}
}
