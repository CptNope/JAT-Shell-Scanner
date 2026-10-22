<?php
/**
 * Scan engine.
 *
 * A scan is a resumable job: each call to step() does as much work as fits in
 * a time budget, then saves its place. That lets the same scan run in one go
 * from WP-CLI, or in small slices from the browser and WP-Cron on hosts with
 * 30-second limits.
 *
 * The scanner is read-only. It never modifies, moves or deletes site files.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Scanner {

	const JOB_OPTION    = 'wp2ss_job';
	const REPORT_OPTION = 'wp2ss_report';
	const MAX_READ      = 5242880;   // Read at most 5 MB of a file for code signatures.
	const MAX_FINDINGS  = 1000;      // Cap so a badly infected site can't bloat the DB.
	const LOCK_STALE    = 600;       // A job untouched for 10 min is considered dead.

	const PHASES = array( 'quick', 'files', 'core', 'log', 'done' );

	/** @var array */
	private $s;

	/** @var array */
	private $sig;

	/** @var float */
	private $deadline;

	/* ================================================================== */
	/* Public API                                                          */
	/* ================================================================== */

	/**
	 * Start a scan, or return the one already running.
	 *
	 * @param array  $args   { log: string, core: bool }.
	 * @param string $source manual|cron|cli.
	 * @param bool   $force  Replace a running scan.
	 * @return array Job state.
	 */
	public static function start( $args = array(), $source = 'manual', $force = false ) {
		$running = self::current();
		if ( $running && ! $force ) {
			return $running;
		}

		$args = wp_parse_args( $args, array( 'log' => '', 'core' => true ) );
		$root = wp_normalize_path( untrailingslashit( WP_CONTENT_DIR ) );

		$state = array(
			'id'       => wp_generate_password( 12, false ),
			'source'   => $source,
			'args'     => $args,
			'started'  => time(),
			'updated'  => time(),
			'phase'    => 'quick',
			'progress' => 0,
			'findings' => array(),
			'overflow' => 0,
			'stats'    => array(
				'files'      => 0,
				'php_files'  => 0,
				'dirs'       => 0,
				'unreadable' => 0,
				'links'      => 0,
			),
			'dirs'     => array( $root ),
			'dirs_done' => 0,
			'cur'      => array( 'dir' => '', 'offset' => 0 ),
			'themes'   => array(),
			'log_pos'  => 0,
			'log'      => array( 'batch_ok' => 0, 'ua' => 0, 'ip' => 0, 'upload' => 0, 'users' => 0, 'sample' => array() ),
		);
		update_site_option( self::JOB_OPTION, $state );
		return $state;
	}

	/** Running job, or null. Stale jobs are discarded. */
	public static function current() {
		$s = get_site_option( self::JOB_OPTION );
		if ( ! is_array( $s ) || empty( $s['id'] ) ) {
			return null;
		}
		if ( time() - (int) $s['updated'] > self::LOCK_STALE ) {
			delete_site_option( self::JOB_OPTION );
			return null;
		}
		return $s;
	}

	public static function cancel() {
		delete_site_option( self::JOB_OPTION );
	}

	/**
	 * Advance the running job.
	 *
	 * @param float $budget Seconds of work to do.
	 * @return array|null Job state, or the finished report (has 'verdict'), or null if nothing is running.
	 */
	public static function step( $budget = 8.0 ) {
		$s = self::current();
		if ( ! $s ) {
			return null;
		}
		$scanner = new self( $s );
		return $scanner->work( $budget );
	}

	/** Run a whole scan in this request (WP-CLI / no-JS fallback). */
	public static function run_all( $args = array(), $source = 'cli', $tick = null ) {
		self::start( $args, $source, true );
		do {
			$r = self::step( 30 );
			if ( $tick && is_array( $r ) && empty( $r['verdict'] ) ) {
				call_user_func( $tick, $r );
			}
		} while ( is_array( $r ) && empty( $r['verdict'] ) );
		return $r;
	}

	public static function last_report() {
		$r = get_site_option( self::REPORT_OPTION );
		return is_array( $r ) ? $r : null;
	}

	/* ------------------------------------------------------------------ */

	public static function signatures() {
		static $sig = null;
		if ( null === $sig ) {
			$sig = include __DIR__ . '/signatures.php';
		}
		return $sig;
	}

	public static function sev_rank( $s ) {
		$map = array( 'critical' => 5, 'high' => 4, 'medium' => 3, 'low' => 2, 'info' => 1 );
		return isset( $map[ $s ] ) ? $map[ $s ] : 0;
	}

	/** Verdict for a set of findings, skipping ignored ones. */
	public static function verdict( $findings, $ignored = array() ) {
		$top        = 0;
		$vulnerable = false;
		foreach ( (array) $findings as $f ) {
			if ( isset( $ignored[ $f['id'] ] ) ) {
				continue;
			}
			// An unpatched version is a risk, not evidence of an attack: it gets its own verdict.
			if ( 'version' === $f['type'] ) {
				$vulnerable = $vulnerable || self::sev_rank( $f['severity'] ) >= 4;
				continue;
			}
			$top = max( $top, self::sev_rank( $f['severity'] ) );
		}
		if ( $top >= 5 ) {
			return 'COMPROMISED';
		}
		if ( $top >= 4 ) {
			return 'SUSPICIOUS';
		}
		if ( $vulnerable ) {
			return 'VULNERABLE';
		}
		if ( $top >= 3 ) {
			return 'REVIEW';
		}
		return 'CLEAN';
	}

	/* ================================================================== */
	/* Job runner                                                          */
	/* ================================================================== */

	private function __construct( $state ) {
		$this->s   = $state;
		$this->sig = self::signatures();
	}

	private function work( $budget ) {
		if ( function_exists( 'set_time_limit' ) && false === strpos( (string) ini_get( 'disable_functions' ), 'set_time_limit' ) ) {
			@set_time_limit( (int) max( 60, $budget * 3 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		$this->deadline = microtime( true ) + max( 0.01, (float) $budget );

		while ( 'done' !== $this->s['phase'] && ! $this->out_of_time() ) {
			switch ( $this->s['phase'] ) {
				case 'quick':
					$this->check_version();
					$this->check_plugins();
					$this->check_mu_plugins();
					$this->check_admins();
					$this->check_app_passwords();
					$this->check_rest_routes();
					$this->next_phase();
					break;

				case 'files':
					if ( $this->walk_files() ) {
						$this->flush_theme_changes();
						$this->next_phase();
					}
					break;

				case 'core':
					if ( ! empty( $this->s['args']['core'] ) ) {
						$this->check_core();
					}
					$this->next_phase();
					break;

				case 'log':
					if ( empty( $this->s['args']['log'] ) || $this->scan_log() ) {
						$this->next_phase();
					}
					break;

				default:
					$this->s['phase'] = 'done';
			}
		}

		if ( 'done' === $this->s['phase'] ) {
			return $this->finish();
		}

		$this->s['updated']  = time();
		$this->s['progress'] = $this->estimate_progress();
		update_site_option( self::JOB_OPTION, $this->s );
		return $this->s;
	}

	private function out_of_time() {
		return microtime( true ) >= $this->deadline;
	}

	private function next_phase() {
		$i                 = array_search( $this->s['phase'], self::PHASES, true );
		$this->s['phase'] = self::PHASES[ min( $i + 1, count( self::PHASES ) - 1 ) ];
	}

	private function estimate_progress() {
		switch ( $this->s['phase'] ) {
			case 'quick':
				return 2;
			case 'files':
				$done  = (int) $this->s['dirs_done'];
				$total = $done + count( $this->s['dirs'] );
				return 5 + (int) floor( 80 * ( $total ? $done / $total : 1 ) );
			case 'core':
				return 88;
			case 'log':
				return 94;
		}
		return 100;
	}

	private function finish() {
		$findings = $this->s['findings'];
		usort(
			$findings,
			function ( $a, $b ) {
				return WP2SS_Scanner::sev_rank( $b['severity'] ) - WP2SS_Scanner::sev_rank( $a['severity'] );
			}
		);
		if ( $this->s['overflow'] ) {
			$findings[] = $this->make( 'high', 'scan', sprintf( '%d more findings were not stored (limit %d).', $this->s['overflow'], self::MAX_FINDINGS ), 'This many findings usually means a heavily compromised site. Restore from a clean backup.' );
		}

		$ignored = (array) get_site_option( 'wp2ss_ignored', array() );
		$report  = array(
			'id'       => $this->s['id'],
			'site'     => network_home_url(),
			'wp'       => get_bloginfo( 'version' ),
			'plugin'   => WP2SS_VERSION,
			'source'   => $this->s['source'],
			'scanned'  => gmdate( 'c' ),
			'duration' => time() - (int) $this->s['started'],
			'stats'    => $this->s['stats'],
			'verdict'  => self::verdict( $findings, $ignored ),
			'findings' => $findings,
		);

		$previous = self::last_report();
		update_site_option( self::REPORT_OPTION, $report );
		delete_site_option( self::JOB_OPTION );

		/**
		 * Fires when a scan completes.
		 *
		 * @param array      $report   The new report.
		 * @param array|null $previous The previous report.
		 */
		do_action( 'wp2ss_scan_complete', $report, $previous );

		return $report;
	}

	/* ================================================================== */
	/* Checks                                                              */
	/* ================================================================== */

	/** 1. Core version against affected ranges. */
	private function check_version() {
		$v = get_bloginfo( 'version' );
		foreach ( $this->sig['vulnerable'] as $r ) {
			if ( version_compare( $v, $r[0], '>=' ) && version_compare( $v, $r[1], '<' ) ) {
				$this->add( $r[2], 'version', "WordPress $v is vulnerable to {$r[3]}.", "Update to {$r[4]} or later now. If this site was online on this version, also treat it as possibly compromised." );
				return;
			}
		}
		$this->add( 'info', 'version', "WordPress $v is not in an affected version range.", 'If the site ran an affected version before updating, it could still have been compromised — check the other findings.' );
	}

	/** 2. Installed plugins. */
	private function check_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		wp_cache_delete( 'plugins', 'plugins' );
		$plugins  = get_plugins();
		$dir      = wp_normalize_path( WP_PLUGIN_DIR );
		$self     = wp_normalize_path( untrailingslashit( WP2SS_DIR ) );
		$cutoff   = $this->sig['disclosure_ts'];
		$recent   = array();

		foreach ( $plugins as $file => $data ) {
			$slug = dirname( $file );
			$path = '.' === $slug ? "$dir/$file" : "$dir/$slug";
			if ( wp_normalize_path( $path ) === $self ) {
				continue;
			}
			$name = isset( $data['Name'] ) ? trim( $data['Name'] ) : '';
			$auth = isset( $data['Author'] ) ? $data['Author'] : '';

			if ( preg_match( '/^wp2shell_[0-9a-f]{4,}$/i', $slug ) || preg_match( '/(^|\/)wp2shell_[0-9a-f]{4,}\.php$/i', $file ) ) {
				$this->add( 'critical', 'plugin', "Plugin matches the wp2shell exploit's naming: $file", 'This is the webshell the public exploit uploads. Keep a copy as evidence, then delete it.', "$dir/$file" );
			}
			if ( 0 === strcasecmp( $name, 'CMSmap' ) || false !== stripos( $slug, 'cmsmap' ) ) {
				$this->add( 'critical', 'plugin', "Plugin named \"CMSmap\" is installed ($file).", 'Seen in the wild as a 150 KB webshell disguised as this security tool.', "$dir/$file" );
			}
			if ( false !== stripos( $name, 'WP Static Cache Helper' ) || false !== stripos( $auth, 'WordPress Performance Team' ) || preg_match( '/wp-static-cache-[0-9a-f]+\.php$/i', $file ) ) {
				$this->add( 'critical', 'plugin', "Fake \"WP Static Cache Helper\" plugin: $file", 'Known wp2shell webshell disguise.', "$dir/$file" );
			}
			if ( preg_match( '/^gg-/i', $name ) || preg_match( '/^gg-/i', $slug ) ) {
				$this->add( 'high', 'plugin', "Plugin with \"gg-\" prefix: $name ($file)", 'Matches the naming of a REST-API webshell seen after wp2shell. Inspect it.', "$dir/$file" );
			}
			if ( '.' === $slug && 'hello.php' !== $file ) {
				$this->add( 'low', 'plugin', "Single-file plugin directly in /plugins: $file", 'Not necessarily bad, but a common webshell pattern. Confirm you installed it.', "$dir/$file" );
			}

			$mtime = @filemtime( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $mtime && $mtime >= $cutoff ) {
				$recent[] = $name ? $name : $slug;
			}
		}

		if ( $recent ) {
			sort( $recent );
			$this->add( 'low', 'plugin', sprintf( '%d plugin(s) installed or updated since wp2shell went public: %s', count( $recent ), implode( ', ', $recent ) ), 'Normal if you updated them. Any you don’t recognise should be investigated.', $dir );
		}

		// Folders with PHP that WordPress doesn't list as plugins.
		$listed = array();
		foreach ( array_keys( $plugins ) as $file ) {
			$listed[ strtok( $file, '/' ) ] = true;
		}
		$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		foreach ( $entries ? $entries : array() as $entry ) {
			if ( '.' === $entry[0] || isset( $listed[ $entry ] ) || ! is_dir( "$dir/$entry" ) || wp_normalize_path( "$dir/$entry" ) === $self ) {
				continue;
			}
			if ( glob( "$dir/$entry/*.php" ) ) {
				$this->add( 'medium', 'plugin', "Folder in /plugins with PHP but no plugin header: $entry", 'It doesn’t appear on the Plugins screen. Inspect it.', "$dir/$entry" );
			}
		}
	}

	/** 3. Must-use plugins run on every request and are invisible on the Plugins screen. */
	private function check_mu_plugins() {
		if ( ! defined( 'WPMU_PLUGIN_DIR' ) || ! is_dir( WPMU_PLUGIN_DIR ) ) {
			return;
		}
		foreach ( (array) glob( WPMU_PLUGIN_DIR . '/*.php' ) as $f ) {
			$m = @filemtime( $f ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $m && $m >= $this->sig['disclosure_ts'] ) {
				$this->add( 'medium', 'mu-plugin', 'Must-use plugin added or changed ' . gmdate( 'Y-m-d', $m ) . ': ' . basename( $f ), 'Must-use plugins run on every page and don’t appear in the normal plugin list. Confirm it’s yours (hosts often add these).', wp_normalize_path( $f ) );
			}
		}
	}

	/** 4. Administrators created since disclosure. */
	private function check_admins() {
		$since    = gmdate( 'Y-m-d H:i:s', $this->sig['disclosure_ts'] );
		$first    = $this->first_user_registered();
		$site_ids = is_multisite() ? get_sites( array( 'fields' => 'ids', 'number' => 500 ) ) : array( get_current_blog_id() );
		$seen     = array();

		foreach ( $site_ids as $blog_id ) {
			$admins = get_users(
				array(
					'blog_id'  => $blog_id,
					'role__in' => array( 'administrator' ),
					'fields'   => array( 'ID', 'user_login', 'user_email', 'user_registered' ),
				)
			);
			foreach ( $admins as $u ) {
				if ( isset( $seen[ $u->ID ] ) || $u->user_registered < $since ) {
					continue;
				}
				$seen[ $u->ID ] = true;
				// An admin created within an hour of the very first account is almost certainly the site owner setting up.
				$at_install = $first && abs( strtotime( $u->user_registered ) - strtotime( $first ) ) < HOUR_IN_SECONDS;
				$this->add(
					$at_install ? 'low' : 'high',
					'user',
					sprintf( 'Administrator "%s" (%s) was created %s UTC%s.', $u->user_login, $u->user_email, $u->user_registered, $at_install ? ', when the site was set up' : '' ),
					$at_install ? 'Looks like the original site admin. Ignore this if so.' : 'wp2shell attacks create rogue admins. If you don’t recognise this account, remove it and reset every admin password.',
					'user:' . $u->ID
				);
			}
		}

		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$u = get_user_by( 'login', $login );
				if ( $u && ! isset( $seen[ $u->ID ] ) && $u->user_registered >= $since ) {
					$this->add( 'high', 'user', "Super admin \"$login\" was created {$u->user_registered} UTC.", 'Confirm this account is legitimate.', 'user:' . $u->ID );
				}
			}
		}
	}

	private function first_user_registered() {
		global $wpdb;
		return $wpdb->get_var( "SELECT MIN(user_registered) FROM {$wpdb->users}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/** 5. Application passwords added to admins since disclosure (quiet persistence). */
	private function check_app_passwords() {
		if ( ! class_exists( 'WP_Application_Passwords' ) ) {
			return;
		}
		$admins = get_users( array( 'role__in' => array( 'administrator' ), 'fields' => array( 'ID', 'user_login' ) ) );
		foreach ( $admins as $u ) {
			foreach ( (array) WP_Application_Passwords::get_user_application_passwords( $u->ID ) as $p ) {
				if ( ! empty( $p['created'] ) && $p['created'] >= $this->sig['disclosure_ts'] ) {
					$this->add( 'medium', 'user', sprintf( 'Application password "%s" added to admin "%s" on %s.', $p['name'], $u->user_login, gmdate( 'Y-m-d', $p['created'] ) ), 'Gives API access without the login screen. Revoke it in the user’s profile if you didn’t create it.', 'user:' . $u->ID );
				}
			}
		}
	}

	/** 6. REST routes registered under known webshell namespaces. */
	private function check_rest_routes() {
		if ( ! function_exists( 'rest_get_server' ) ) {
			return;
		}
		$namespaces = rest_get_server()->get_namespaces();
		foreach ( $this->sig['rest_namespaces'] as $ns ) {
			if ( in_array( $ns, $namespaces, true ) ) {
				$this->add( 'critical', 'rest', "REST namespace \"$ns\" is registered.", 'Used by a webshell plugin seen after wp2shell exploitation. Find the plugin that registers it (see the code findings).', 'rest:' . $ns );
			}
		}
	}

	/**
	 * 7. Walk wp-content, one directory at a time, resumable mid-directory.
	 *
	 * @return bool True when the walk is complete.
	 */
	private function walk_files() {
		$root      = wp_normalize_path( untrailingslashit( WP_CONTENT_DIR ) );
		$self      = wp_normalize_path( untrailingslashit( WP2SS_DIR ) );
		$data_dirs = $this->sig['data_dirs'];

		while ( ! $this->out_of_time() ) {
			if ( '' === $this->s['cur']['dir'] ) {
				if ( ! $this->s['dirs'] ) {
					return true;
				}
				$this->s['cur'] = array( 'dir' => array_pop( $this->s['dirs'] ), 'offset' => 0 );
			}

			$dir     = $this->s['cur']['dir'];
			$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $entries ) {
				$this->s['stats']['unreadable']++;
				$this->s['cur'] = array( 'dir' => '', 'offset' => 0 );
				continue;
			}

			$n = count( $entries );
			for ( $i = $this->s['cur']['offset']; $i < $n; $i++ ) {
				if ( $this->out_of_time() ) {
					$this->s['cur']['offset'] = $i;
					return false;
				}
				$name = $entries[ $i ];
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				$path = $dir . '/' . $name;
				$rel  = ltrim( substr( $path, strlen( $root ) ), '/' );

				if ( is_link( $path ) ) {
					$this->s['stats']['links']++;
					continue;
				}
				if ( is_dir( $path ) ) {
					if ( $path === $self ) {
						continue;
					}
					if ( preg_match( '/^wp2shell_[0-9a-f]{4,}$/i', $name ) && 0 !== strpos( $rel, 'plugins/' ) ) {
						$this->add( 'critical', 'file', "wp2shell staging folder: wp-content/$rel", 'Left over from the exploit’s plugin upload.', $path );
					}
					$this->s['dirs'][] = $path;
					continue;
				}

				$this->s['stats']['files']++;
				$this->check_file( $path, $rel, $name, $data_dirs );
			}

			$this->s['dirs_done']++;
			$this->s['stats']['dirs']++;
			$this->s['cur'] = array( 'dir' => '', 'offset' => 0 );
		}
		return false;
	}

	private function check_file( $path, $rel, $name, $data_dirs ) {
		$top = strtok( $rel, '/' );

		if ( 0 === stripos( $name, 'temp-write-test-' ) ) {
			$this->add( 'high', 'file', "Write-test file: wp-content/$rel", 'The public wp2shell exploit creates these to check it can write to the site.', $path );
		}
		if ( preg_match( '/^wp2shell_[0-9a-f]{4,}\.zip$/i', $name ) ) {
			$this->add( 'critical', 'file', "wp2shell plugin archive: wp-content/$rel", 'The exploit’s uploaded payload.', $path );
		}
		if ( '.htaccess' === $name && in_array( $top, $data_dirs, true ) ) {
			$ht = @file_get_contents( $path, false, null, 0, 65536 ); // phpcs:ignore
			if ( $ht && preg_match( '/(AddHandler|SetHandler|AddType)[^\n]*(php|x-httpd)/i', $ht ) ) {
				$this->add( 'high', 'file', "Upload-folder .htaccess enables PHP: wp-content/$rel", 'Attackers add this so uploaded PHP will run. Remove those lines.', $path );
			}
		}

		if ( ! preg_match( $this->sig['php_ext'], $name ) ) {
			return;
		}
		$this->s['stats']['php_files']++;

		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$sha1 = @sha1_file( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $sha1 && isset( $this->sig['sha1'][ $sha1 ] ) ) {
			$this->add( 'critical', 'hash', "Known wp2shell webshell: wp-content/$rel", "File hash $sha1 matches a published indicator ({$this->sig['sha1'][ $sha1 ]}).", $path );
			return;
		}

		$code = ( $size > 0 && $size <= self::MAX_READ ) ? @file_get_contents( $path ) : false; // phpcs:ignore

		// PHP inside data folders.
		if ( in_array( $top, $data_dirs, true ) && ! ( is_string( $code ) && self::is_empty_php( $code ) ) ) {
			if ( 'cache' === $top && preg_match( $this->sig['cache_engines'], $rel ) ) {
				// Cache plugin internals: not reported.
			} else {
				$this->add(
					'high',
					'file',
					"PHP file in a data folder: wp-content/$rel",
					'cache' === $top ? 'wp2shell attackers have written webshells into wp-content/cache/. Open it and confirm what it is.' : 'PHP shouldn’t live in this folder. Open it and confirm what it is.',
					$path
				);
			}
		}

		if ( '.' === $name[0] ) {
			$this->add( 'medium', 'file', "Hidden PHP file: wp-content/$rel", 'Hidden PHP files are a common way to tuck away backdoors.', $path );
		}

		if ( is_string( $code ) ) {
			$this->scan_code( $code, $path, $rel );
		}

		$m = @filemtime( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( 'themes' === $top && $m >= $this->sig['disclosure_ts'] ) {
			$theme = strtok( substr( $rel, 7 ), '/' );
			if ( ! isset( $this->s['themes'][ $theme ] ) ) {
				$this->s['themes'][ $theme ] = array( 'n' => 0, 'files' => array() );
			}
			$this->s['themes'][ $theme ]['n']++;
			if ( count( $this->s['themes'][ $theme ]['files'] ) < 5 ) {
				$this->s['themes'][ $theme ]['files'][] = $rel;
			}
		}
	}

	private function scan_code( $code, $path, $rel ) {
		foreach ( $this->sig['code'] as $s ) {
			if ( preg_match( $s[1], $code ) ) {
				$this->add( $s[0], 'code', "{$s[2]}: wp-content/$rel", 'Open the file to confirm. If it’s malicious: keep a copy as evidence, remove it, then rotate passwords and salts.', $path );
				return;
			}
		}
		if ( false !== stripos( $code, 'register_rest_route' )
			&& preg_match( '/permission_callback[\'"]?\s*=>\s*[\'"]__return_true[\'"]/i', $code )
			&& preg_match( '/\b(passthru|shell_exec|system|proc_open|popen)\s*\(/i', $code ) ) {
			$this->add( 'critical', 'code', "Public REST endpoint that runs shell commands: wp-content/$rel", 'Matches the REST-API webshell seen after wp2shell exploitation.', $path );
		}
	}

	/** "Silence is golden" style files: nothing but tags, comments and whitespace. */
	public static function is_empty_php( $code ) {
		if ( strlen( $code ) > 2048 ) {
			return false;
		}
		if ( function_exists( 'token_get_all' ) ) {
			foreach ( @token_get_all( $code ) as $t ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( ! is_array( $t ) ) {
					return false;
				}
				if ( ! in_array( $t[0], array( T_OPEN_TAG, T_CLOSE_TAG, T_COMMENT, T_DOC_COMMENT, T_WHITESPACE ), true )
					&& ! ( T_INLINE_HTML === $t[0] && '' === trim( $t[1] ) ) ) {
					return false;
				}
			}
			return true;
		}
		$stripped = preg_replace( array( '#/\*.*?\*/#s', '#//[^\n]*#', '/#[^\n]*/', '/<\?php|\?>/' ), '', $code );
		return '' === trim( $stripped );
	}

	private function flush_theme_changes() {
		foreach ( $this->s['themes'] as $theme => $t ) {
			$this->add( 'low', 'file', sprintf( 'Theme "%s": %d PHP file(s) changed since wp2shell went public.', $theme, $t['n'] ), 'Normal after a theme update or your own edits. Otherwise inspect: ' . implode( ', ', $t['files'] ) . ( $t['n'] > 5 ? ' …' : '' ), wp_normalize_path( WP_CONTENT_DIR . '/themes/' . $theme ) );
		}
		$this->s['themes'] = array();
	}

	/** 8. Core files vs wordpress.org checksums. */
	private function check_core() {
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$v      = get_bloginfo( 'version' );
		$locale = get_locale();
		$sums   = get_core_checksums( $v, $locale ? $locale : 'en_US' );
		if ( ! is_array( $sums ) && 'en_US' !== $locale ) {
			$sums = get_core_checksums( $v, 'en_US' );
		}
		if ( ! is_array( $sums ) ) {
			$this->add( 'info', 'core', 'Couldn’t download core checksums from wordpress.org, so core files weren’t verified.', 'Your server may block outbound requests. Run `wp core verify-checksums` if you have WP-CLI.' );
			return;
		}

		$abs = wp_normalize_path( ABSPATH );
		$bad = array();
		foreach ( $sums as $file => $md5 ) {
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			$p = $abs . $file;
			if ( is_file( $p ) && md5_file( $p ) !== $md5 ) {
				$bad[] = $file;
			}
		}
		foreach ( array_slice( $bad, 0, 25 ) as $file ) {
			$this->add( 'high', 'core', "Modified WordPress core file: $file", 'Core files shouldn’t change. Keep a copy as evidence, then reinstall core (Dashboard → Updates → Re-install).', $abs . $file );
		}
		if ( count( $bad ) > 25 ) {
			$this->add( 'high', 'core', ( count( $bad ) - 25 ) . ' more modified core files.', 'Reinstall WordPress core.' );
		}

		foreach ( array( 'wp-admin', 'wp-includes' ) as $d ) {
			if ( ! is_dir( $abs . $d ) ) {
				continue;
			}
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $abs . $d, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY,
				RecursiveIteratorIterator::CATCH_GET_CHILD
			);
			foreach ( $it as $f ) {
				if ( preg_match( $this->sig['php_ext'], $f->getFilename() ) ) {
					$rel = substr( wp_normalize_path( $f->getPathname() ), strlen( $abs ) );
					if ( ! isset( $sums[ $rel ] ) ) {
						$this->add( 'high', 'core', "Unknown PHP file in a core folder: $rel", 'Not part of WordPress — very likely a backdoor.', $abs . $rel );
					}
				}
			}
		}

		foreach ( (array) glob( $abs . '*.php' ) as $f ) {
			$b = basename( $f );
			if ( ! isset( $sums[ $b ] ) && ! in_array( $b, $this->sig['root_allow'], true ) ) {
				$this->add( 'medium', 'core', "Unknown PHP file in the site root: $b", 'Confirm you or your host put it there.', wp_normalize_path( $f ) );
			}
		}
	}

	/**
	 * 9. Access log. Resumable by byte offset.
	 *
	 * @return bool True when finished.
	 */
	private function scan_log() {
		$log = $this->s['args']['log'];
		if ( ! @is_readable( $log ) || is_dir( $log ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$this->add( 'info', 'log', "Access log not readable: $log", 'Check the path, and that PHP is allowed to read it (open_basedir / permissions).' );
			return true;
		}
		$gz = (bool) preg_match( '/\.gz$/i', $log );
		$fh = $gz ? @gzopen( $log, 'rb' ) : @fopen( $log, 'rb' ); // phpcs:ignore
		if ( ! $fh ) {
			return true;
		}
		$gz ? gzseek( $fh, $this->s['log_pos'] ) : fseek( $fh, $this->s['log_pos'] );

		$c   = &$this->s['log'];
		$ua  = $this->sig['user_agents'];
		$ips = $this->sig['ips'];
		$n   = 0;
		$eof = false;

		while ( true ) {
			$line = $gz ? gzgets( $fh, 16384 ) : fgets( $fh, 16384 );
			if ( false === $line ) {
				$eof = true;
				break;
			}
			$hit = false;
			if ( preg_match( '#(rest_route=/?batch/v1|/wp-json/batch/v1)#i', $line ) && preg_match( '#"\s+(200|207)\s#', $line ) ) {
				$c['batch_ok']++;
				$hit = true;
			}
			if ( preg_match( $ua, $line ) ) {
				$c['ua']++;
				$hit = true;
			}
			$first = strtok( $line, ' ' );
			if ( in_array( $first, $ips, true ) ) {
				$c['ip']++;
				$hit = true;
			}
			if ( false !== strpos( $line, 'action=upload-plugin' ) ) {
				$c['upload']++;
			}
			if ( false !== strpos( $line, 'users?context=edit' ) ) {
				$c['users']++;
			}
			if ( $hit && count( $c['sample'] ) < 3 ) {
				$c['sample'][] = trim( substr( $line, 0, 240 ) );
			}
			if ( 0 === ( ++$n % 5000 ) && $this->out_of_time() ) {
				break;
			}
		}
		$this->s['log_pos'] = $gz ? gztell( $fh ) : ftell( $fh );
		$gz ? gzclose( $fh ) : fclose( $fh );

		if ( ! $eof ) {
			return false;
		}

		$sample = $c['sample'] ? ' Example: ' . implode( ' | ', $c['sample'] ) : '';
		if ( $c['batch_ok'] ) {
			$this->add( 'critical', 'log', "{$c['batch_ok']} successful (200/207) requests to the batch API.", 'A high-confidence sign the exploit worked.' . $sample, $log );
		}
		if ( $c['ua'] ) {
			$this->add( 'high', 'log', "{$c['ua']} requests from wp2shell exploit tools (user-agent).", 'The site was targeted. Check whether anything above shows it succeeded.' . ( $c['batch_ok'] ? '' : $sample ), $log );
		}
		if ( $c['ip'] ) {
			$this->add( 'high', 'log', "{$c['ip']} requests from published wp2shell attacker IPs.", '', $log );
		}
		if ( $c['upload'] ) {
			$this->add( 'medium', 'log', "{$c['upload']} plugin-upload requests.", 'Match these against uploads you made yourself.', $log );
		}
		if ( $c['users'] ) {
			$this->add( 'medium', 'log', "{$c['users']} admin user-enumeration requests (users?context=edit).", 'Seen as wp2shell follow-up activity.', $log );
		}
		if ( ! $c['batch_ok'] && ! $c['ua'] && ! $c['ip'] ) {
			$this->add( 'info', 'log', 'No wp2shell markers in the access log.', 'Logs rotate — older activity may be in archived logs (.gz files work too).', $log );
		}
		return true;
	}

	/* ================================================================== */
	/* Helpers                                                             */
	/* ================================================================== */

	private function make( $severity, $type, $message, $advice = '', $location = '' ) {
		return array(
			'id'       => substr( md5( $type . '|' . $location . '|' . $message ), 0, 12 ),
			'severity' => $severity,
			'type'     => $type,
			'message'  => $message,
			'advice'   => $advice,
			'location' => $location,
		);
	}

	private function add( $severity, $type, $message, $advice = '', $location = '' ) {
		if ( count( $this->s['findings'] ) >= self::MAX_FINDINGS ) {
			$this->s['overflow']++;
			return;
		}
		$this->s['findings'][] = $this->make( $severity, $type, $message, $advice, $location );
	}
}
