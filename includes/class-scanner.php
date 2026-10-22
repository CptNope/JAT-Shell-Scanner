<?php
/**
 * Scan engine.
 *
 * A scan is a resumable job. Each call to step() does as much work as fits in
 * a time budget, saves its place, and returns. The same scan can therefore run
 * in one go from WP-CLI, or in small slices from the browser and WP-Cron on
 * hosts with 30-second limits — and pick up where it left off after a pause.
 *
 * Only one request works on a job at a time (a database lock), so two browser
 * tabs or a browser plus a scheduled scan can't trample each other.
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
	const LOCK_NAME     = 'wp2ss_lock';
	const STATE_VERSION = 2;

	const MAX_READ     = 5242880;        // Read whole files up to 5 MB for code signatures…
	const EDGE_READ    = 1048576;        // …and the first + last 1 MB of anything bigger.
	const MAX_FINDINGS = 1000;           // Cap so a badly infected site can't bloat the database.
	const LOCK_TTL     = 300;            // A step lock older than this belongs to a dead request.
	const JOB_EXPIRE   = DAY_IN_SECONDS; // A job with no progress for a day is abandoned.
	const MAX_LINKS    = 200;            // Symlinked folders followed per scan.

	const PHASES = array( 'quick', 'files', 'core', 'log', 'done' );

	/** Files that ship with this plugin. Any other PHP in its folder is suspicious. */
	const OWN_PHP = array(
		'wp2shell-scanner.php',
		'uninstall.php',
		'includes/class-admin.php',
		'includes/class-cli.php',
		'includes/class-cron.php',
		'includes/class-scanner.php',
		'includes/class-settings.php',
		'includes/class-site-health.php',
		'includes/class-updater.php',
		'includes/signatures.php',
		'tests/false-positives.php', // Only present in a GitHub source download.
	);

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
		$root = self::content_root();

		$state = array(
			'v'         => self::STATE_VERSION,
			'id'        => wp_generate_password( 12, false ),
			'source'    => $source,
			'args'      => $args,
			'started'   => time(),
			'updated'   => time(),
			'phase'     => 'quick',
			'progress'  => 0,
			'findings'  => array(),
			'overflow'  => 0,
			'errors'    => 0,
			'stats'     => array(
				'files'      => 0,
				'php_files'  => 0,
				'dirs'       => 0,
				'unreadable' => 0,
				'links'      => 0,
				'large'      => 0,
			),
			'dirs'      => array( $root ),
			'dirs_done' => 0,
			'cur'       => array( 'dir' => '', 'offset' => 0 ),
			'followed'  => array(),
			'themes'    => array(),
			'core'      => null,
			'log_pos'   => 0,
			'log'       => array( 'batch_ok' => 0, 'ua' => 0, 'ip' => 0, 'upload' => 0, 'users' => 0, 'sample' => array() ),
		);
		self::save_state( $state );
		return $state;
	}

	/** Running job, or null. Abandoned or outdated jobs are discarded. */
	public static function current() {
		$s = self::fresh_option( self::JOB_OPTION );
		if ( ! is_array( $s ) || empty( $s['id'] ) ) {
			return null;
		}
		if ( ( isset( $s['v'] ) ? (int) $s['v'] : 0 ) !== self::STATE_VERSION || time() - (int) $s['updated'] > self::JOB_EXPIRE ) {
			delete_site_option( self::JOB_OPTION );
			return null;
		}
		return $s;
	}

	public static function cancel() {
		delete_site_option( self::JOB_OPTION );
		self::unlock( null );
	}

	/**
	 * Advance the running job.
	 *
	 * @param float $budget Seconds of work to do.
	 * @return array|null Job state (with 'busy' => true if another request holds the lock),
	 *                    the finished report (has 'verdict'), or null if nothing is running.
	 */
	public static function step( $budget = 8.0 ) {
		if ( ! self::current() ) {
			return null;
		}
		$token = self::lock();
		if ( ! $token ) {
			$s         = self::current();
			$s['busy'] = true;
			return $s;
		}
		try {
			$s = self::current(); // Re-read now that we hold the lock.
			if ( ! $s ) {
				return self::last_report();
			}
			$scanner = new self( $s );
			return $scanner->work( (float) apply_filters( 'wp2ss_step_budget', $budget ) );
		} finally {
			self::unlock( $token );
		}
	}

	/** Run a whole scan in this request (WP-CLI / no-JavaScript fallback). */
	public static function run_all( $args = array(), $source = 'cli', $tick = null ) {
		self::start( $args, $source, true );
		$guard = 0;
		do {
			$r = self::step( 30 );
			if ( is_array( $r ) && ! empty( $r['busy'] ) ) {
				usleep( 250000 );
			} elseif ( $tick && is_array( $r ) && empty( $r['verdict'] ) ) {
				call_user_func( $tick, $r );
			}
		} while ( is_array( $r ) && empty( $r['verdict'] ) && ++$guard < 100000 );
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
			/**
			 * Filter the indicators the scanner uses (add your own code signatures, hashes, IPs…).
			 *
			 * @param array $sig See includes/signatures.php for the structure.
			 */
			$sig = apply_filters( 'wp2ss_signatures', $sig );
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
		return '' === trim( (string) $stripped );
	}

	/* ================================================================== */
	/* Storage & locking                                                   */
	/* ================================================================== */

	private static function content_root() {
		return wp_normalize_path( untrailingslashit( WP_CONTENT_DIR ) );
	}

	/** Read an option bypassing any copy cached earlier in this request. */
	private static function fresh_option( $name ) {
		if ( is_multisite() ) {
			wp_cache_delete( get_current_network_id() . ':' . $name, 'site-options' );
			wp_cache_delete( get_current_network_id() . ':notoptions', 'site-options' );
		} else {
			wp_cache_delete( $name, 'options' );
			wp_cache_delete( 'notoptions', 'options' );
		}
		return get_site_option( $name );
	}

	private static function save_state( $state ) {
		update_site_option( self::JOB_OPTION, $state );
	}

	/** Options table of the main site: it has a unique key on option_name, which makes an atomic lock. */
	private static function lock_table() {
		global $wpdb;
		return is_multisite() ? $wpdb->get_blog_prefix( get_main_site_id() ) . 'options' : $wpdb->options;
	}

	/** @return string|false Lock token, or false if another live request holds it. */
	private static function lock() {
		global $wpdb;
		$table = self::lock_table();
		$token = time() . '|' . wp_generate_password( 8, false );

		for ( $try = 0; $try < 2; $try++ ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$ok = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO `$table` (option_name, option_value, autoload) VALUES (%s, %s, 'no')", self::LOCK_NAME, $token ) );
			if ( $ok ) {
				return $token;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$held = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM `$table` WHERE option_name = %s", self::LOCK_NAME ) );
			if ( null === $held ) {
				continue; // Released between our two queries.
			}
			if ( time() - (int) strtok( (string) $held, '|' ) < self::LOCK_TTL ) {
				return false;
			}
			// Stale lock from a request that died: remove exactly that one, then retry.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( $wpdb->prepare( "DELETE FROM `$table` WHERE option_name = %s AND option_value = %s", self::LOCK_NAME, $held ) );
		}
		return false;
	}

	private static function unlock( $token ) {
		global $wpdb;
		$table = self::lock_table();
		if ( null === $token ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( $wpdb->prepare( "DELETE FROM `$table` WHERE option_name = %s", self::LOCK_NAME ) );
		} elseif ( $token ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( $wpdb->prepare( "DELETE FROM `$table` WHERE option_name = %s AND option_value = %s", self::LOCK_NAME, $token ) );
		}
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
					foreach ( array( 'check_version', 'check_plugins', 'check_mu_plugins', 'check_admins', 'check_app_passwords', 'check_rest_routes', 'check_own_folder' ) as $check ) {
						$this->guarded( array( $this, $check ), $check );
					}
					$this->next_phase();
					break;

				case 'files':
					$done = $this->guarded( array( $this, 'walk_files' ), 'file scan', true );
					if ( $done ) {
						$this->flush_theme_changes();
						$this->next_phase();
					}
					break;

				case 'core':
					$done = empty( $this->s['args']['core'] ) || $this->guarded( array( $this, 'check_core' ), 'core check', true );
					if ( $done ) {
						$this->next_phase();
					}
					break;

				case 'log':
					$done = empty( $this->s['args']['log'] ) || $this->guarded( array( $this, 'scan_log' ), 'log scan', true );
					if ( $done ) {
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
		self::save_state( $this->s );
		return $this->s;
	}

	/**
	 * Run one check so that an unexpected error is reported instead of killing the scan.
	 *
	 * @return mixed The check's return value; $on_error if it threw (so the phase moves on).
	 */
	private function guarded( $fn, $label, $on_error = null ) {
		try {
			return call_user_func( $fn );
		} catch ( Throwable $e ) {
			$this->s['errors']++;
			$this->add( 'info', 'scan', sprintf( 'The %s stopped early: %s', str_replace( array( 'check_', '_' ), array( '', ' ' ), $label ), $e->getMessage() ), 'The rest of the scan still ran. If this keeps happening, please report it with the message above.' );
			if ( 'file scan' === $label ) {
				// Skip the directory that caused it and carry on with the rest.
				$this->s['cur'] = array( 'dir' => '', 'offset' => 0 );
				return ! $this->s['dirs'];
			}
			return $on_error;
		}
	}

	private function out_of_time() {
		return microtime( true ) >= $this->deadline;
	}

	private function next_phase() {
		$i                = array_search( $this->s['phase'], self::PHASES, true );
		$this->s['phase'] = self::PHASES[ min( (int) $i + 1, count( self::PHASES ) - 1 ) ];
	}

	private function estimate_progress() {
		switch ( $this->s['phase'] ) {
			case 'quick':
				return 2;
			case 'files':
				$done  = (int) $this->s['dirs_done'];
				$total = $done + count( $this->s['dirs'] );
				return 5 + (int) floor( 78 * ( $total ? $done / $total : 1 ) );
			case 'core':
				$c = $this->s['core'];
				return 85 + ( $c && $c['total'] ? (int) floor( 9 * $c['pos'] / $c['total'] ) : 0 );
			case 'log':
				return 95;
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
			'stats'    => $this->s['stats'] + array( 'errors' => $this->s['errors'] ),
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
		$plugins = get_plugins();
		$dir     = wp_normalize_path( untrailingslashit( WP_PLUGIN_DIR ) );
		$self    = wp_normalize_path( untrailingslashit( WP2SS_DIR ) );
		$cutoff  = $this->sig['disclosure_ts'];
		$recent  = array();

		foreach ( $plugins as $file => $data ) {
			$slug = dirname( $file );
			$path = '.' === $slug ? "$dir/$file" : "$dir/$slug";
			if ( wp_normalize_path( $path ) === $self ) {
				continue; // This plugin's own files are checked by check_own_folder().
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
			if ( ! $m || $m < $this->sig['disclosure_ts'] ) {
				continue;
			}
			$b    = basename( $f );
			$host = (bool) preg_match( $this->sig['host_mu_plugins'], $b );
			$this->add(
				$host ? 'low' : 'medium',
				'mu-plugin',
				'Must-use plugin added or changed ' . gmdate( 'Y-m-d', $m ) . ': ' . $b . ( $host ? ' (looks like your host’s)' : '' ),
				$host ? 'Hosts update their own must-use plugins regularly. Ignore this if the name matches your host.' : 'Must-use plugins run on every page and don’t appear in the normal plugin list. Confirm it’s yours or your host’s.',
				wp_normalize_path( $f )
			);
		}
	}

	/** 4. Administrators created since disclosure — one query, any number of sites. */
	private function check_admins() {
		global $wpdb;
		$since = gmdate( 'Y-m-d H:i:s', $this->sig['disclosure_ts'] );
		$first = $this->first_user_registered();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT u.ID, u.user_login, u.user_email, u.user_registered
				 FROM {$wpdb->users} u
				 INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
				 WHERE m.meta_key LIKE %s AND m.meta_value LIKE %s AND u.user_registered >= %s
				 GROUP BY u.ID, u.user_login, u.user_email, u.user_registered
				 LIMIT 200",
				$wpdb->esc_like( $wpdb->base_prefix ) . '%capabilities',
				'%' . $wpdb->esc_like( '"administrator"' ) . '%',
				$since
			)
		);
		$seen = array();
		foreach ( (array) $rows as $u ) {
			$seen[ $u->ID ] = true;
			// An admin created within an hour of the very first account is almost certainly the owner setting up.
			$at_install = $first && abs( strtotime( $u->user_registered ) - strtotime( $first ) ) < HOUR_IN_SECONDS;
			$this->add(
				$at_install ? 'low' : 'high',
				'user',
				sprintf( 'Administrator "%s" (%s) was created %s UTC%s.', $u->user_login, $u->user_email, $u->user_registered, $at_install ? ', when the site was set up' : '' ),
				$at_install ? 'Looks like the original site admin. Ignore this if so.' : 'wp2shell attacks create rogue admins. If you don’t recognise this account, remove it and reset every admin password.',
				'user:' . $u->ID
			);
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
		global $wpdb;
		if ( ! class_exists( 'WP_Application_Passwords' ) ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$ids = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT user_id FROM {$wpdb->usermeta} WHERE meta_key LIKE %s AND meta_value LIKE %s LIMIT 500",
				$wpdb->esc_like( $wpdb->base_prefix ) . '%capabilities',
				'%' . $wpdb->esc_like( '"administrator"' ) . '%'
			)
		);
		foreach ( (array) $ids as $id ) {
			foreach ( (array) WP_Application_Passwords::get_user_application_passwords( (int) $id ) as $p ) {
				if ( ! empty( $p['created'] ) && $p['created'] >= $this->sig['disclosure_ts'] ) {
					$u = get_userdata( (int) $id );
					$this->add( 'medium', 'user', sprintf( 'Application password "%s" added to admin "%s" on %s.', $p['name'], $u ? $u->user_login : $id, gmdate( 'Y-m-d', $p['created'] ) ), 'Gives API access without the login screen. Revoke it in the user’s profile if you didn’t create it.', 'user:' . (int) $id );
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

	/** 7. This plugin's own folder: a backdoor hidden here must not go unnoticed. */
	private function check_own_folder() {
		$self = wp_normalize_path( untrailingslashit( WP2SS_DIR ) );
		$it   = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $self, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::LEAVES_ONLY,
			RecursiveIteratorIterator::CATCH_GET_CHILD
		);
		foreach ( $it as $f ) {
			$rel = ltrim( substr( wp_normalize_path( $f->getPathname() ), strlen( $self ) ), '/' );
			if ( preg_match( $this->sig['php_ext'], $rel ) && ! in_array( $rel, self::OWN_PHP, true ) ) {
				$this->add( 'high', 'file', "Unexpected PHP file inside wp2shell Scanner’s own folder: $rel", 'This plugin doesn’t ship that file. Attackers sometimes hide in security plugins. Reinstall the plugin from the official release.', $self . '/' . $rel );
			}
		}
	}

	/**
	 * 8. Walk wp-content one directory at a time; resumable mid-directory.
	 *
	 * Uses readdir() rather than scandir() so a folder with hundreds of
	 * thousands of files doesn't have to be loaded into memory at once.
	 *
	 * @return bool True when the walk is complete.
	 */
	private function walk_files() {
		$root = self::content_root();

		while ( ! $this->out_of_time() ) {
			if ( '' === $this->s['cur']['dir'] ) {
				if ( ! $this->s['dirs'] ) {
					return true;
				}
				$this->s['cur'] = array( 'dir' => array_pop( $this->s['dirs'] ), 'offset' => 0 );
			}

			$dir = $this->s['cur']['dir'];
			$dh  = @opendir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! $dh ) {
				$this->s['stats']['unreadable']++;
				$this->s['cur'] = array( 'dir' => '', 'offset' => 0 );
				continue;
			}

			// Skip what an earlier slice already handled.
			$i = 0;
			while ( $i < $this->s['cur']['offset'] && false !== readdir( $dh ) ) {
				$i++;
			}

			$finished = true;
			while ( false !== ( $name = readdir( $dh ) ) ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition
				$i++;
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				$path = $dir . '/' . $name;
				$rel  = ltrim( substr( $path, strlen( $root ) ), '/' );

				if ( is_link( $path ) && is_dir( $path ) ) {
					$this->maybe_follow_link( $path, $dir );
				} elseif ( is_dir( $path ) ) {
					if ( preg_match( '/^wp2shell_[0-9a-f]{4,}$/i', $name ) && 0 !== strpos( $rel, 'plugins/' ) ) {
						$this->add( 'critical', 'file', "wp2shell staging folder: wp-content/$rel", 'Left over from the exploit’s plugin upload.', $path );
					}
					$this->s['dirs'][] = $path;
				} else {
					$this->s['stats']['files']++;
					try {
						$this->check_file( $path, $rel, $name );
					} catch ( Throwable $e ) {
						$this->s['stats']['unreadable']++;
					}
				}

				if ( $this->out_of_time() ) {
					$this->s['cur']['offset'] = $i;
					$finished                 = false;
					break;
				}
			}
			closedir( $dh );

			if ( ! $finished ) {
				return false;
			}
			$this->s['dirs_done']++;
			$this->s['stats']['dirs']++;
			$this->s['cur'] = array( 'dir' => '', 'offset' => 0 );
		}
		return false;
	}

	/**
	 * Symlinked folders (common for plugins on some hosts and dev setups) are
	 * followed once each, unless they point back up the tree (a loop).
	 */
	private function maybe_follow_link( $path, $parent ) {
		$real        = realpath( $path );
		$parent_real = realpath( $parent );
		if ( ! $real || ! $parent_real || count( $this->s['followed'] ) >= self::MAX_LINKS
			|| in_array( $real, $this->s['followed'], true )
			|| 0 === strpos( wp_normalize_path( $parent_real ) . '/', wp_normalize_path( $real ) . '/' ) ) {
			$this->s['stats']['links']++;
			return;
		}
		$this->s['followed'][] = $real;
		$this->s['dirs'][]     = $path;
	}

	private function check_file( $path, $rel, $name ) {
		$top       = (string) strtok( $rel, '/' );
		$data_dirs = $this->sig['data_dirs'];

		if ( 0 === stripos( $name, 'temp-write-test-' ) ) {
			$this->add( 'high', 'file', "Write-test file: wp-content/$rel", 'The public wp2shell exploit creates these to check it can write to the site.', $path );
		}
		if ( preg_match( '/^wp2shell_[0-9a-f]{4,}\.zip$/i', $name ) ) {
			$this->add( 'critical', 'file', "wp2shell plugin archive: wp-content/$rel", 'The exploit’s uploaded payload.', $path );
		}
		if ( '.htaccess' === $name && in_array( $top, $data_dirs, true ) ) {
			$ht = @file_get_contents( $path, false, null, 0, 65536 ); // phpcs:ignore
			if ( $ht && preg_match( '/^\s*(AddHandler|SetHandler|AddType|php_flag\s+engine\s+on)[^\n]*(php|x-httpd|engine)/im', $ht ) ) {
				$this->add( 'high', 'file', "Upload-folder .htaccess enables PHP: wp-content/$rel", 'Attackers add this so uploaded PHP will run. Remove those lines.', $path );
			}
		}

		if ( ! preg_match( $this->sig['php_ext'], $name ) ) {
			return;
		}
		$this->s['stats']['php_files']++;

		$size = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$code = false;
		if ( $size > 0 && $size <= self::MAX_READ ) {
			$code = @file_get_contents( $path ); // phpcs:ignore
			$sha1 = is_string( $code ) ? sha1( $code ) : false;
		} else {
			$sha1 = @sha1_file( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $size > self::MAX_READ ) {
				// Too big to read whole: check the start and the end, where injected code usually sits.
				$this->s['stats']['large']++;
				$code = $this->read_edges( $path, $size );
			}
		}

		if ( $sha1 && isset( $this->sig['sha1'][ $sha1 ] ) ) {
			$this->add( 'critical', 'hash', "Known wp2shell webshell: wp-content/$rel", "File hash $sha1 matches a published indicator ({$this->sig['sha1'][ $sha1 ]}).", $path );
			return;
		}

		// PHP inside data folders.
		if ( in_array( $top, $data_dirs, true ) && ! ( is_string( $code ) && $size <= self::MAX_READ && self::is_empty_php( $code ) ) ) {
			if ( ! ( 'cache' === $top && preg_match( $this->sig['cache_engines'], $rel ) ) ) {
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

		if ( is_string( $code ) && '' !== $code ) {
			$this->scan_code( $code, $path, $rel );
		}

		$m = @filemtime( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( 'themes' === $top && $m >= $this->sig['disclosure_ts'] ) {
			$theme = (string) strtok( substr( $rel, 7 ), '/' );
			if ( ! isset( $this->s['themes'][ $theme ] ) ) {
				$this->s['themes'][ $theme ] = array( 'n' => 0, 'files' => array() );
			}
			$this->s['themes'][ $theme ]['n']++;
			if ( count( $this->s['themes'][ $theme ]['files'] ) < 5 ) {
				$this->s['themes'][ $theme ]['files'][] = $rel;
			}
		}
	}

	private function read_edges( $path, $size ) {
		$fh = @fopen( $path, 'rb' ); // phpcs:ignore
		if ( ! $fh ) {
			return false;
		}
		$head = (string) fread( $fh, self::EDGE_READ );
		fseek( $fh, max( 0, $size - self::EDGE_READ ) );
		$tail = (string) fread( $fh, self::EDGE_READ );
		fclose( $fh );
		return $head . "\n" . $tail;
	}

	private function scan_code( $code, $path, $rel ) {
		$hit = self::match_code( $code );
		if ( $hit ) {
			$this->add( $hit[0], 'code', "{$hit[1]}: wp-content/$rel", $hit[2], $path );
		}
	}

	/**
	 * Check PHP source against the code signatures. Pure function: also used by
	 * the false-positive test that runs over popular plugins in CI.
	 *
	 * @param string $code PHP source.
	 * @return array|null [ severity, description, advice ] or null.
	 */
	public static function match_code( $code ) {
		$sig    = self::signatures();
		$advice = 'Open the file to confirm. If it’s malicious: keep a copy as evidence, remove it, then rotate passwords and salts.';
		foreach ( $sig['code'] as $s ) {
			if ( preg_match( $s[1], $code ) ) {
				return array( $s[0], $s[2], $advice );
			}
		}
		if ( false !== stripos( $code, 'register_rest_route' )
			&& preg_match( '/permission_callback[\'"]?\s*=>\s*[\'"]__return_true[\'"]/i', $code )
			&& preg_match( '/(?<![\w>:$])(passthru|shell_exec|system|exec|proc_open|popen)\s*\([^;]{0,160}(get_param|base64_decode|\$_(POST|GET|REQUEST)|\$request\s*\[)/i', $code ) ) {
			return array( 'critical', 'Public REST endpoint that runs shell commands', 'Matches the REST-API webshell seen after wp2shell exploitation.' );
		}
		// Weaker signal: request input, a decoder and eval/assert all in one small file.
		if ( strlen( $code ) < 200000
			&& preg_match( '/\b(eval|assert)\s*\(/i', $code )
			&& preg_match( '/\b(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(/i', $code )
			&& preg_match( '/\$_(POST|GET|REQUEST|COOKIE)\b/', $code ) ) {
			return array( 'medium', 'Combines web-request input, decoding and eval', 'A pattern webshells often use. Some legitimate plugins do this too — open the file and check.' );
		}
		return null;
	}

	private function flush_theme_changes() {
		foreach ( $this->s['themes'] as $theme => $t ) {
			$this->add( 'low', 'file', sprintf( 'Theme "%s": %d PHP file(s) changed since wp2shell went public.', $theme, $t['n'] ), 'Normal after a theme update or your own edits. Otherwise inspect: ' . implode( ', ', $t['files'] ) . ( $t['n'] > 5 ? ' …' : '' ), wp_normalize_path( WP_CONTENT_DIR . '/themes/' . $theme ) );
		}
		$this->s['themes'] = array();
	}

	/**
	 * 9. Core files vs wordpress.org checksums. Resumable.
	 *
	 * @return bool True when finished.
	 */
	private function check_core() {
		$abs = wp_normalize_path( ABSPATH );

		if ( null === $this->s['core'] ) {
			if ( null === $this->core_sums() ) {
				$this->add( 'info', 'core', 'Couldn’t download core checksums from wordpress.org, so core files weren’t verified.', 'Your server may block outbound requests. Your host can run `wp core verify-checksums` for you.' );
				return true;
			}
			$this->s['core'] = array( 'pos' => 0, 'total' => count( $this->core_sums() ), 'bad' => array(), 'extra' => false );
		}

		$sums = $this->core_sums();
		if ( null === $sums ) {
			return true; // Cache vanished mid-scan and wordpress.org is unreachable now: skip quietly.
		}
		$keys = array_keys( $sums );
		$c    = &$this->s['core'];

		while ( $c['pos'] < $c['total'] ) {
			$file = $keys[ $c['pos'] ];
			$c['pos']++;
			if ( 0 !== strpos( $file, 'wp-content/' ) ) {
				$p = $abs . $file;
				if ( is_file( $p ) && md5_file( $p ) !== $sums[ $file ] ) {
					$c['bad'][] = $file;
				}
			}
			if ( 0 === $c['pos'] % 100 && $this->out_of_time() ) {
				return false;
			}
		}

		if ( ! $c['extra'] ) {
			foreach ( array_slice( $c['bad'], 0, 25 ) as $file ) {
				$this->add( 'high', 'core', "Modified WordPress core file: $file", 'Core files shouldn’t change. Keep a copy as evidence, then reinstall core (Dashboard → Updates → Re-install).', $abs . $file );
			}
			if ( count( $c['bad'] ) > 25 ) {
				$this->add( 'high', 'core', ( count( $c['bad'] ) - 25 ) . ' more modified core files.', 'Reinstall WordPress core.' );
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
			$c['extra'] = true;
			$c['bad']   = array();
		}
		return true;
	}

	/** Core checksums for this version, cached for a day. Null if unavailable. */
	private function core_sums() {
		static $mem = null;
		if ( null !== $mem ) {
			return $mem;
		}
		$v      = get_bloginfo( 'version' );
		$locale = get_locale();
		$key    = 'wp2ss_core_' . md5( $v . '|' . $locale );
		$sums   = get_site_transient( $key );
		if ( ! is_array( $sums ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
			$sums = get_core_checksums( $v, $locale ? $locale : 'en_US' );
			if ( ! is_array( $sums ) && 'en_US' !== $locale ) {
				$sums = get_core_checksums( $v, 'en_US' );
			}
			if ( ! is_array( $sums ) || ! $sums ) {
				return null;
			}
			set_site_transient( $key, $sums, DAY_IN_SECONDS );
		}
		$mem = $sums;
		return $mem;
	}

	/**
	 * 10. Access log. Resumable by byte offset.
	 *
	 * @return bool True when finished.
	 */
	private function scan_log() {
		$log = $this->s['args']['log'];
		if ( ! @is_file( $log ) || ! @is_readable( $log ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
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
		$ips = array_flip( $this->sig['ips'] );
		$n   = 0;
		$eof = false;

		while ( true ) {
			$line = $gz ? gzgets( $fh, 16384 ) : fgets( $fh, 16384 );
			if ( false === $line ) {
				$eof = true;
				break;
			}
			$hit = false;
			if ( preg_match( '#(rest_route=(/|%2F)?batch(/|%2F)v1|/wp-json/batch/v1)#i', $line ) && preg_match( '#"\s+(200|207)\s#', $line ) ) {
				$c['batch_ok']++;
				$hit = true;
			}
			if ( preg_match( $ua, $line ) ) {
				$c['ua']++;
				$hit = true;
			}
			if ( isset( $ips[ (string) strtok( $line, " \t" ) ] ) ) {
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

	/**
	 * Build a finding. The ID ignores numbers in the message, so dates and
	 * counts changing between scans don't resurrect a finding you ignored.
	 */
	private function make( $severity, $type, $message, $advice = '', $location = '' ) {
		return array(
			'id'       => substr( md5( $type . '|' . $location . '|' . preg_replace( '/\d+/', '#', $message ) ), 0, 12 ),
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
