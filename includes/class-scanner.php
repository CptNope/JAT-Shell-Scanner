<?php
/**
 * Scan engine.
 *
 * Looks for two attacks:
 *  - PHP2Shell (CVE-2026-109618 / CVE-2026-109619): bugs in the PHP engine.
 *  - wp2shell (CVE-2026-63030 / CVE-2026-60137): bugs in WordPress core.
 * Both end the same way — an attacker running code on the server — so most
 * checks look for what they leave behind: webshells, rogue admins, changed
 * files and traces in the server logs.
 *
 * A scan is a resumable job. Each call to step() does as much work as fits in
 * a time budget, saves its place (down to the position inside a folder), and
 * returns. The same scan can run in one go from WP-CLI, or in small slices from
 * the browser and WP-Cron on hosts with 30-second limits.
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

	const JOB_OPTION      = 'wp2ss_job';
	const REPORT_OPTION   = 'wp2ss_report';
	const IGNORE_OPTION   = 'wp2ss_ignored';
	const BASELINE_OPTION = 'wp2ss_admins';
	const LOCK_NAME       = 'wp2ss_lock';
	const STATE_VERSION   = 3;

	const MAX_READ     = 5242880;        // Read whole files up to 5 MB for code signatures…
	const EDGE_READ    = 1048576;        // …and the first + last 1 MB of anything bigger.
	const IMAGE_READ   = 4096;           // Bytes of each uploaded image checked for hidden PHP.
	const MAX_FINDINGS = 1000;           // Cap so a badly infected site can't bloat the database.
	const LOCK_TTL     = 300;            // A step lock older than this belongs to a dead request.
	const JOB_EXPIRE   = DAY_IN_SECONDS; // A job with no progress for a day is abandoned.
	const MAX_LINKS    = 200;            // Symlinked folders followed per scan.
	const MAX_TRIES    = 2;              // Attempts at a risky step before skipping it.

	const PHASES = array( 'quick', 'files', 'core', 'logs', 'done' );

	/** Types of finding that describe a weakness, not evidence of an attack. */
	const VULN_TYPES = array( 'version', 'php' );

	/** PHP files that ship with this plugin (used when there is no release manifest). */
	const OWN_PHP = array(
		'wp2shell-scanner.php',
		'uninstall.php',
		'includes/class-admin.php',
		'includes/class-cli.php',
		'includes/class-cron.php',
		'includes/class-env.php',
		'includes/class-fixes.php',
		'includes/class-fleet.php',
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
	 * @param array  $args   { log: string, error_log: string, core: bool }.
	 * @param string $source manual|cron|cli.
	 * @param bool   $force  Replace a running scan.
	 * @return array Job state.
	 */
	public static function start( $args = array(), $source = 'manual', $force = false ) {
		$running = self::current();
		if ( $running && ! $force ) {
			return $running;
		}

		$args = wp_parse_args( $args, array( 'log' => '', 'error_log' => '', 'core' => true ) );

		$state = array(
			'v'         => self::STATE_VERSION,
			'id'        => wp_generate_password( 12, false ),
			'source'    => $source,
			'args'      => $args,
			'env'       => WP2SS_Env::get(),
			'started'   => time(),
			'updated'   => time(),
			'phase'     => 'quick',
			'progress'  => 0,
			'findings'  => array(),
			'overflow'  => 0,
			'errors'    => 0,
			'tries'     => array(),
			'stats'     => array(
				'files'      => 0,
				'php_files'  => 0,
				'dirs'       => 0,
				'unreadable' => 0,
				'links'      => 0,
				'large'      => 0,
			),
			'roots'     => self::walk_roots(),
			'root'      => null,
			'frames'    => array(),
			'followed'  => array(),
			'themes'    => array(),
			'core'      => null,
			'logs'      => null,
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
			$s = self::current();
			if ( $s ) {
				$s['busy'] = true;
			}
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
	/* Signatures, severities, verdicts                                    */
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

	/**
	 * Overall verdict, skipping ignored findings.
	 *
	 * Weaknesses (an unpatched WordPress or PHP) give "VULNERABLE"; evidence of
	 * an attack gives "SUSPICIOUS" or "COMPROMISED", which take precedence.
	 */
	public static function verdict( $findings, $ignored = null ) {
		$ignored    = null === $ignored ? self::ignored() : $ignored;
		$top        = 0;
		$vulnerable = false;
		foreach ( (array) $findings as $f ) {
			if ( self::is_ignored( $f, $ignored ) ) {
				continue;
			}
			$rank = self::sev_rank( $f['severity'] );
			if ( in_array( $f['type'], self::VULN_TYPES, true ) ) {
				if ( $rank >= 4 ) {
					$vulnerable = true;
				} else {
					$top = max( $top, min( $rank, 3 ) );
				}
				continue;
			}
			$top = max( $top, $rank );
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

	/* ------------------------------------------------------------------ */
	/* Ignore list (signed, so it can't be forged through the database)    */
	/* ------------------------------------------------------------------ */

	public static function ignored() {
		$i = get_site_option( self::IGNORE_OPTION, array() );
		return is_array( $i ) ? $i : array();
	}

	private static function ignore_sig( $id, $sha1 ) {
		// wp_salt() comes from wp-config.php, which an attacker with only database access can't read.
		return hash_hmac( 'sha256', 'wp2ss-ignore|' . $id . '|' . $sha1, wp_salt( 'auth' ) );
	}

	/** Is this finding on the ignore list — validly signed, and (for files) unchanged since? */
	public static function is_ignored( $f, $ignored = null ) {
		$ignored = null === $ignored ? self::ignored() : $ignored;
		if ( empty( $f['id'] ) || empty( $ignored[ $f['id'] ] ) || ! is_array( $ignored[ $f['id'] ] ) ) {
			return false;
		}
		$e    = $ignored[ $f['id'] ];
		$sha1 = isset( $e['sha1'] ) ? (string) $e['sha1'] : '';
		if ( empty( $e['sig'] ) || ! hash_equals( self::ignore_sig( $f['id'], $sha1 ), (string) $e['sig'] ) ) {
			return false;
		}
		// A file that changed after it was ignored gets looked at again.
		return '' === $sha1 || empty( $f['sha1'] ) || $sha1 === $f['sha1'];
	}

	/** Ignore (or stop ignoring) a finding from the last report. */
	public static function set_ignored( $id, $ignore, $user_id = 0 ) {
		$id      = preg_replace( '/[^a-f0-9]/', '', strtolower( (string) $id ) );
		$ignored = self::ignored();
		if ( ! $id ) {
			return false;
		}
		if ( ! $ignore ) {
			unset( $ignored[ $id ] );
		} else {
			$sha1   = '';
			$report = self::last_report();
			foreach ( $report ? $report['findings'] : array() as $f ) {
				if ( $f['id'] === $id && ! empty( $f['sha1'] ) ) {
					$sha1 = $f['sha1'];
				}
			}
			$ignored[ $id ] = array(
				'sha1' => $sha1,
				'sig'  => self::ignore_sig( $id, $sha1 ),
				'by'   => (int) $user_id,
				'at'   => time(),
			);
		}
		update_site_option( self::IGNORE_OPTION, $ignored );
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Helpers shared with tests                                           */
	/* ------------------------------------------------------------------ */

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

	/** Files that stop immediately unless WordPress loaded them (not callable directly from the web). */
	public static function is_guarded_php( $code ) {
		$head = preg_replace( '#/\*.*?\*/|//[^\n]*|\#[^\n]*#s', '', substr( $code, 0, 2048 ) );
		return (bool) preg_match( '/^\s*<\?php\s*(?:(?:exit|die|__halt_compiler)\b|if\s*\(\s*!\s*defined\s*\(\s*[\'"](?:ABSPATH|WPINC)[\'"]\s*\)\s*\)\s*\{?\s*(?:exit|die)\b|defined\s*\(\s*[\'"](?:ABSPATH|WPINC)[\'"]\s*\)\s*(?:\|\||or)\s*(?:exit|die)\b)/i', (string) $head );
	}

	/**
	 * A "PHP" file that can't run anything: it only answers 404 (or exits) and
	 * stops, and the rest is plain data. Plugins use this to keep keys and
	 * settings out of reach of the web. Nothing after the guard is executed.
	 */
	public static function is_inert_data( $code ) {
		$code = (string) $code;
		if ( ! preg_match( '/^\s*<\?php\s+(?:header\s*\(\s*([\'"])HTTP\/1\.[01]\s+40[34][^\'"]*\1\s*\)\s*;\s*)?(?:exit|die)\s*(?:\(\s*(?:[\'"][^\'"<]*[\'"])?\s*\))?\s*;?\s*(__halt_compiler\s*\(\s*\)\s*;\s*)?\?>/i', $code, $m ) ) {
			return false;
		}
		// No second PHP block anywhere after the guard (unless the compiler was halted).
		return ! empty( $m[2] ) || false === strpos( substr( $code, strlen( $m[0] ) ), '<?' );
	}

	/**
	 * The Installatron Worker: the temporary script the Installatron one-click
	 * installer (used by IONOS and many other hosts) puts in the site root.
	 * Recognised by its structure, not its name: the header, a single signature
	 * check using Installatron's pinned public key, and every command handled
	 * only after an unsigned request has been turned away.
	 */
	public static function is_installatron_worker( $code, $keys ) {
		$code = (string) $code;
		if ( ! preg_match( '/^<\?php\s*\/\*\s*Plugin Name:\s*Installatron Worker\b/', $code ) || false === strpos( $code, 'Installatron LLC' ) || 1 !== substr_count( $code, 'function __i_verify_signature' ) ) {
			return false;
		}
		$fn  = strpos( $code, 'function __i_verify_signature' );
		$ret = strpos( $code, 'return $rsa->verify($message, $signature);', $fn );
		if ( false === $ret || ! preg_match( "/loadKey\\('-----BEGIN PUBLIC KEY-----([A-Za-z0-9+\\/=\\s]+)-----END PUBLIC KEY-----'\\)/", substr( $code, $fn, $ret - $fn ), $k ) ) {
			return false;
		}
		if ( ! in_array( hash( 'sha256', preg_replace( '/\s+/', '', $k[1] ) ), (array) $keys, true ) ) {
			return false;
		}
		$deny = strpos( $code, 'I_ACCESS_DENIED' );
		// Needles split so this file doesn't match its own code signatures.
		$eval = strpos( $code, 'ev' . 'al(' );
		$cmd  = strpos( $code, '$_PO' . 'ST["cmd"]' );
		return false !== $deny && $deny > $ret && ( false === $eval || $eval > $deny ) && ( false === $cmd || $cmd > $deny );
	}

	/**
	 * Check PHP source against the code signatures. Pure function: also used by
	 * the false-positive test that runs over popular plugins in CI.
	 *
	 * @param string $code PHP source.
	 * @return array|null [ severity, description, advice ] for the most severe match, or null.
	 */
	public static function match_code( $code ) {
		$sig    = self::signatures();
		$advice = 'Open the file to confirm. If it’s malicious: keep a copy as evidence, remove it, then change passwords, keys and salts.';
		$best   = null;
		foreach ( $sig['code'] as $s ) {
			if ( ( ! $best || self::sev_rank( $s[0] ) > self::sev_rank( $best[0] ) ) && preg_match( $s[1], $code ) ) {
				$best = array( $s[0], $s[2], $advice );
			}
		}
		if ( ( ! $best || 'critical' !== $best[0] )
			&& false !== stripos( $code, 'register_rest_route' )
			&& false !== stripos( $code, 'permission_callback' )
			&& preg_match( '/(?<![\w>:$])(passthru|shell_exec|system|exec|proc_open|popen)\s*\([^;]{0,160}(get_param|base64_decode|\$_(POST|GET|REQUEST)|\$request\s*\[)/i', $code ) ) {
			$best = array( 'critical', 'REST endpoint that runs shell commands sent to it', 'Matches the REST-API webshell seen after wp2shell exploitation.' );
		}
		if ( ! $best
			&& strlen( $code ) < 200000
			&& preg_match( '/\b(eval|assert)\s*\(/i', $code )
			&& preg_match( '/\b(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(/i', $code )
			&& preg_match( '/\$_(POST|GET|REQUEST|COOKIE)\b/', $code ) ) {
			$best = array( 'medium', 'Combines web-request input, decoding and eval', 'A pattern webshells often use. Some legitimate plugins do this too — open the file and check.' );
		}
		return $best;
	}

	/* ================================================================== */
	/* Storage & locking                                                   */
	/* ================================================================== */

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

	/** Is this still the job on record? (It may have been cancelled or replaced while we worked.) */
	private function still_current() {
		$s = self::fresh_option( self::JOB_OPTION );
		return is_array( $s ) && isset( $s['id'] ) && $s['id'] === $this->s['id'];
	}

	/* ------------------------------------------------------------------ */
	/* Paths: kept in job state safely even if not valid UTF-8             */
	/* ------------------------------------------------------------------ */

	/** Valid UTF-8? (seems_utf8() is deprecated since WordPress 6.9.) */
	private static function is_utf8( $s ) {
		return 1 === @preg_match( '//u', (string) $s ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	private static function enc( $path ) {
		return self::is_utf8( $path ) ? $path : 'b64:' . base64_encode( $path ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
	}

	private static function dec( $path ) {
		return 0 === strpos( $path, 'b64:' ) ? (string) base64_decode( substr( $path, 4 ) ) : $path; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
	}

	/** Text safe to store and show: invalid UTF-8 (e.g. Latin-1 file names) is made printable. */
	private static function clean_text( $s ) {
		$s = (string) $s;
		if ( self::is_utf8( $s ) ) {
			return $s;
		}
		return function_exists( 'mb_convert_encoding' ) ? mb_convert_encoding( $s, 'UTF-8', 'ISO-8859-1' ) : preg_replace( '/[\x80-\xFF]/', '?', $s );
	}

	/**
	 * Folders to walk, each with the name it appears under in findings.
	 * wp-content first; then plugin, must-use and upload folders that live elsewhere.
	 */
	private static function walk_roots() {
		$content = wp_normalize_path( untrailingslashit( WP_CONTENT_DIR ) );
		$roots   = array( array( self::enc( $content ), 'wp-content' ) );
		$extra   = array(
			'wp-content/plugins'    => WP_PLUGIN_DIR,
			'wp-content/mu-plugins' => defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : '',
		);
		$up = wp_upload_dir( null, false );
		if ( ! empty( $up['basedir'] ) ) {
			$extra['wp-content/uploads'] = $up['basedir'];
		}
		foreach ( $extra as $label => $dir ) {
			$dir = wp_normalize_path( untrailingslashit( (string) $dir ) );
			if ( $dir && is_dir( $dir ) && 0 !== strpos( $dir . '/', $content . '/' ) ) {
				$roots[] = array( self::enc( $dir ), $label );
			}
		}
		return $roots;
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
		$this->deadline = microtime( true ) + max( 0.0005, (float) $budget );

		while ( 'done' !== $this->s['phase'] && ! $this->out_of_time() ) {
			switch ( $this->s['phase'] ) {
				case 'quick':
					$checks = array( 'check_php', 'check_tmp', 'check_server', 'check_version', 'check_plugins', 'check_mu_plugins', 'check_admins', 'check_admin_baseline', 'check_app_passwords', 'check_roles', 'check_rest_routes', 'check_root_files', 'check_own_folder' );
					foreach ( $checks as $check ) {
						$this->guarded( array( $this, $check ), $check );
					}
					$this->next_phase();
					break;

				case 'files':
					if ( $this->guarded( array( $this, 'walk_files' ), 'file scan', true ) ) {
						$this->flush_theme_changes();
						$this->next_phase();
					}
					break;

				case 'core':
					if ( empty( $this->s['args']['core'] ) || $this->guarded( array( $this, 'check_core' ), 'core check', true ) ) {
						$this->next_phase();
					}
					break;

				case 'logs':
					if ( $this->guarded( array( $this, 'scan_logs' ), 'log scan', true ) ) {
						$this->next_phase();
					}
					break;

				default:
					$this->s['phase'] = 'done';
			}
		}

		if ( ! $this->still_current() ) {
			return null; // Cancelled or replaced while we worked: don't write it back.
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
	 * @return mixed The check's return value, or $on_error if it threw (so the phase moves on).
	 */
	private function guarded( $fn, $label, $on_error = null ) {
		try {
			return call_user_func( $fn );
		} catch ( Throwable $e ) {
			$this->s['errors']++;
			$this->add( 'info', 'scan', sprintf( 'The %s stopped early: %s', str_replace( array( 'check_', '_' ), array( '', ' ' ), $label ), $e->getMessage() ), 'The rest of the scan still ran. If this keeps happening, please report it with the message above.' );
			if ( 'file scan' === $label && $this->s['frames'] ) {
				array_pop( $this->s['frames'] ); // Skip the folder that caused it and carry on.
				return false;
			}
			return $on_error;
		}
	}

	/**
	 * Count an attempt at a step that can hang or crash the request (and
	 * therefore never save its state). After MAX_TRIES it gets skipped.
	 */
	private function attempt( $key ) {
		$n                       = isset( $this->s['tries'][ $key ] ) ? $this->s['tries'][ $key ] : 0;
		$this->s['tries'][ $key ] = $n + 1;
		if ( $n >= self::MAX_TRIES ) {
			return false;
		}
		self::save_state( $this->s ); // Persist the count before the risky work.
		return true;
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
				$roots_total = count( $this->s['roots'] ) + ( $this->s['root'] ? 1 : 0 ) + (int) ( isset( $this->s['roots_done'] ) ? $this->s['roots_done'] : 0 );
				$done        = isset( $this->s['roots_done'] ) ? (int) $this->s['roots_done'] : 0;
				$frac        = 0;
				if ( $this->s['root'] && ! empty( $this->s['frames'] ) && ! empty( $this->s['root']['count'] ) ) {
					$frac = min( 1, $this->s['frames'][0][1] / max( 1, $this->s['root']['count'] ) );
				}
				return 5 + (int) floor( 78 * ( ( $done + $frac ) / max( 1, $roots_total ) ) );
			case 'core':
				$c = $this->s['core'];
				return 85 + ( $c && ! empty( $c['total'] ) ? (int) floor( 7 * $c['pos'] / $c['total'] ) : 0 );
			case 'logs':
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
			$findings[] = $this->make( 'high', 'scan', sprintf( '%d more findings were not stored (limit %d).', $this->s['overflow'], self::MAX_FINDINGS ), 'This many findings usually means a heavily compromised site. Restore from a clean backup.', '', 'overflow' );
		}
		if ( empty( $this->s['args']['core'] ) ) {
			$setting_off = ! WP2SS_Settings::get()['core'];
			$findings[]  = $this->make(
				$setting_off ? 'low' : 'info',
				'scan',
				$setting_off ? 'Core files weren’t verified: that check is turned off in the settings.' : 'Core files weren’t verified in this scan (skipped on request).',
				$setting_off ? 'Turn “Verify core files” back on unless your server can’t reach wordpress.org. If you didn’t turn it off, someone else may have.' : '',
				'',
				'core-off'
			);
		}

		$env    = $this->s['env'];
		$report = array(
			'id'       => $this->s['id'],
			'site'     => network_home_url(),
			'wp'       => get_bloginfo( 'version' ),
			'php'      => array(
				'version' => $env['version'],
				'sapi'    => $env['sapi'],
				'source'  => $env['source'],
			),
			'plugin'   => WP2SS_VERSION,
			'source'   => $this->s['source'],
			'args'     => array(
				'core'      => (bool) $this->s['args']['core'],
				'log'       => (string) $this->s['args']['log'],
				'error_log' => (string) $this->s['args']['error_log'],
			),
			'scanned'  => gmdate( 'c' ),
			'duration' => time() - (int) $this->s['started'],
			'stats'    => $this->s['stats'] + array( 'errors' => $this->s['errors'] ),
			'verdict'  => self::verdict( $findings ),
			'findings' => $findings,
		);

		$previous = self::last_report();
		update_site_option( self::REPORT_OPTION, $report );
		delete_site_option( self::JOB_OPTION );
		$this->save_admin_baseline();

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
	/* Checks: PHP2Shell                                                   */
	/* ================================================================== */

	/** 1. Is the web server's PHP patched against PHP2Shell? */
	private function check_php() {
		$e      = $this->s['env'];
		list( $status ) = WP2SS_Env::php2shell_status_env( $e, $this->sig );
		$v      = $e['version'];
		$pkg    = isset( $e['pkg'] ) ? (string) $e['pkg'] : '';
		$fixed  = isset( $this->sig['php_fixed'][ $e['branch'] ] ) ? $this->sig['php_fixed'][ $e['branch'] ] : '';
		$distro = WP2SS_Env::maybe_backported( $e );
		$modphp = 'apache2handler' === $e['sapi'];
		$where  = 'cli' === $e['source']
			? ' (This is the command-line PHP. Open the WordPress dashboard once so the scanner can see the PHP your website actually runs.)'
			: '';
		$risk   = $modphp ? ' It runs as Apache mod_php, the highest-risk setup for this bug.' : '';
		$rotate = ' Once PHP is updated, change your passwords, API keys and the salts in wp-config.php — PHP2Shell can leak memory contents.';

		switch ( $status ) {
			case 'fixed':
			case 'newer':
				$this->add( 'info', 'php', 'PHP ' . $v . ( $pkg ? " (package $pkg)" : '' ) . " includes the PHP2Shell fix.$where", 'Nothing to do for PHP2Shell. If this server ran an older PHP after October 17, 2026, see the other findings.', '', 'php-status' );
				break;

			case 'pkg-vulnerable':
				$this->add( 'high', 'php', "PHP $v is vulnerable to PHP2Shell: its operating-system package ($pkg) is older than the one that fixes CVE-2026-109618 and CVE-2026-109619.$where", 'Ask your host to install the latest PHP security updates (on Ubuntu/Debian: apt upgrade) and restart PHP — the scanner page has a ready-to-send message.' . $risk . $rotate, '', 'php-status' );
				break;

			case 'build-after-fix':
				$this->add( 'medium', 'php', sprintf( 'PHP %s is older than the PHP2Shell fix by number, but was built on %s — after the fix came out — so it probably carries a backport.%s', $v, gmdate( 'Y-m-d', (int) $e['build'] ), $where ), 'Ask your host to confirm CVE-2026-109618 and CVE-2026-109619 are fixed in this build, then click Ignore.' . $risk, '', 'php-status' );
				break;

			case 'vulnerable':
				if ( $distro ) {
					$this->add( 'medium', 'php', "PHP $v is older than the PHP2Shell fix ($fixed), but it looks like an operating-system package, which is often patched without changing the version number.$where", 'Ask your host to confirm this server is patched for CVE-2026-109618 and CVE-2026-109619 (the scanner page has a ready-to-send message).' . $risk, '', 'php-status' );
				} else {
					$this->add( 'high', 'php', "PHP $v is vulnerable to PHP2Shell (CVE-2026-109618 / CVE-2026-109619). The fix is in PHP $fixed.$where", 'Ask your host to update PHP now — the scanner page has a ready-to-send message.' . $risk . $rotate, '', 'php-status' );
				}
				break;

			case 'backport-only':
				$this->add( $distro ? 'medium' : 'high', 'php', "PHP $v has no official PHP2Shell fix: the PHP team only published source patches for the {$e['branch']} branch.$where", ( $distro ? 'Your host’s operating system may include those patches — ask them to confirm. ' : 'Unless your host applied those patches, this server is vulnerable. ' ) . 'Plan a move to PHP 8.2 or newer.' . $risk . $rotate, '', 'php-status' );
				break;

			default: // no-fix.
				$this->add( 'critical', 'php', "PHP $v will never get a PHP2Shell fix — the {$e['branch']} branch is long out of support.$where", 'Ask your host to move this site to PHP 8.2 or newer as soon as possible.' . $risk . $rotate, '', 'php-status' );
		}

		// Temporary protections, worth knowing about while PHP isn't confirmed patched.
		if ( in_array( $status, array( 'vulnerable', 'pkg-vulnerable', 'backport-only', 'no-fix', 'build-after-fix' ), true ) ) {
			$on  = array();
			$off = array();
			$this->truthy( $e['upload_progress'] ) ? ( $off[] = 'session.upload_progress.enabled is on (0 partly protects against CVE-2026-109619)' ) : ( $on[] = 'session upload progress is off (partial)' );
			'-1' === (string) $e['memory_limit'] ? ( $on[] = 'memory_limit is -1 (partial; it must be enforced so sites can’t change it)' ) : ( $off[] = 'memory_limit is ' . $e['memory_limit'] . ' (PHP’s advisory: -1, enforced with php_admin_value, partly protects against CVE-2026-109618)' );
			if ( version_compare( $e['branch'], '8.5', '>=' ) ) {
				$this->truthy( $e['fatal_bt'] ) ? ( $off[] = 'fatal_error_backtraces is on (set it to 0)' ) : ( $on[] = 'fatal_error_backtraces is off' );
			}
			if ( ! empty( $e['post_max_size'] ) && wp_convert_hr_to_bytes( $e['post_max_size'] ) > 32 * MB_IN_BYTES ) {
				$off[] = 'post_max_size is ' . $e['post_max_size'] . ' (PHP advises keeping it low)';
			}
			if ( isset( $e['max_nesting'] ) && '' !== (string) $e['max_nesting'] && (int) $e['max_nesting'] > 32 ) {
				$off[] = 'max_input_nesting_level is ' . (int) $e['max_nesting'] . ' (PHP advises reducing it)';
			}
			$this->add( 'info', 'php', 'Temporary PHP2Shell protections: ' . ( $on ? 'in place — ' . implode( ', ', $on ) . '. ' : '' ) . ( $off ? 'missing — ' . implode( ', ', $off ) . '.' : '' ), 'None of these is a complete fix — only updating PHP is. Your host must set them in php.ini or the PHP-FPM pool (php_admin_value, not .user.ini or ini_set), then fully restart PHP. PHP’s advisory also suggests pm.max_requests = 1 for PHP-FPM, and no operating-system memory limits (RLIMIT_AS / RLIMIT_DATA) on PHP.', '', 'php-mitigations' );
		}

		// Did this site run an unpatched PHP during the attack window, even if it's fixed now?
		if ( in_array( $status, array( 'fixed', 'newer' ), true ) && ! empty( $e['history'] ) ) {
			foreach ( $e['history'] as $h ) {
				list( $hs ) = WP2SS_Env::php2shell_status_env(
					array(
						'version' => $h['v'],
						'pkg'     => isset( $h['pkg'] ) ? $h['pkg'] : '',
						'build'   => isset( $h['build'] ) ? $h['build'] : 0,
					),
					$this->sig
				);
				if ( ! in_array( $hs, array( 'fixed', 'newer', 'build-after-fix' ), true ) && (int) $h['last'] >= $this->sig['php2shell_ts'] ) {
					$this->add( 'medium', 'php', sprintf( 'This site ran PHP %s (not patched for PHP2Shell) until %s, after attacks began on October 17, 2026.', $h['v'], gmdate( 'Y-m-d', (int) $h['last'] ) ), 'Check the other findings for signs of a break-in, and change passwords, API keys and the salts in wp-config.php, since PHP2Shell can leak memory.' . ( ! empty( $h['extra'] ) ? ' (That PHP was an OS package, so it may have been patched already.)' : '' ), '', 'php-history' );
					break;
				}
			}
		}
	}

	/** 1b. PHP2Shell's second-stage malware is dropped in /tmp as "nfs". */
	private function check_tmp() {
		$dirs = array_unique( array_filter( array( wp_normalize_path( untrailingslashit( (string) sys_get_temp_dir() ) ), '/tmp', '/var/tmp', '/dev/shm' ) ) );
		foreach ( $dirs as $d ) {
			$entries = @scandir( $d ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! $entries ) {
				continue; // Not readable here (open_basedir etc.): nothing to say.
			}
			foreach ( array_slice( $entries, 0, 5000 ) as $name ) {
				$p = "$d/$name";
				if ( '.' === $name || '..' === $name || ! @is_file( $p ) || @is_link( $p ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					continue;
				}
				if ( 'nfs' !== strtolower( $name ) && 0 !== stripos( $name, 'nfs.' ) ) {
					$this->check_tmp_file( $d, $p, $name );
					continue;
				}
				$hash = @filesize( $p ) < 50 * MB_IN_BYTES ? (string) @hash_file( 'sha256', $p ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( $hash && isset( $this->sig['php2shell_files'][ $hash ] ) ) {
					$this->add( 'critical', 'file', "PHP2Shell malware found: $p", 'This is the program attackers install after exploiting PHP2Shell (' . $this->sig['php2shell_files'][ $hash ] . '). Tell your host immediately: the whole server is compromised, not just this site.', $p, '', '' );
				} else {
					$this->add( 'high', 'file', "Suspicious file named \"nfs\" in $d", 'PHP2Shell attacks download a program called nfs into the temporary folder. Ask your host to check it.', $p );
				}
			}
		}
	}

	/**
	 * Other things attackers stage in temporary folders: programs in shared
	 * memory (/dev/shm), and PHP files written since the attacks began.
	 */
	private function check_tmp_file( $dir, $p, $name ) {
		$recent = (int) @filemtime( $p ) >= $this->sig['php2shell_ts']; // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( '/dev/shm' === $dir || $recent ) {
			$head = (string) @file_get_contents( $p, false, null, 0, 4 ); // phpcs:ignore
			if ( "\x7fELF" === $head ) {
				$this->add( '/dev/shm' === $dir ? 'high' : 'medium', 'file', "Program file in the temporary folder $dir: $name", 'Attackers stage their tools in temporary folders and shared memory after breaking in through PHP. Ask your host what it is.', $p );
				return;
			}
		}
		if ( $recent && preg_match( $this->sig['php_ext'], $name ) ) {
			$this->add( 'medium', 'file', "PHP file in the temporary folder $dir: $name", 'Webshells are often written to temporary folders first. Ask your host what it is.', $p );
		}
	}

	/**
	 * 1c. Server-wide persistence and PHP sessions with code in them — the
	 * checks a PHP2Shell incident response starts with. Silent where PHP may
	 * not look.
	 */
	private function check_server() {
		$pre = @is_readable( '/etc/ld.so.preload' ) ? (string) @file_get_contents( '/etc/ld.so.preload', false, null, 0, 4096 ) : ''; // phpcs:ignore
		$pre = trim( preg_replace( '/^\s*#.*$/m', '', $pre ) );
		if ( '' !== $pre ) {
			$this->add( 'high', 'file', 'The server loads a library into every program (/etc/ld.so.preload): ' . self::clean_text( substr( strtok( $pre, "\n" ), 0, 120 ) ), 'Rootkits use this to hide themselves. A few security agents use it too — ask your host whether they put it there.', '/etc/ld.so.preload', 'ld-preload' );
		}

		// Session files with PHP code in them (written by an attack, then included).
		$path = (string) ini_get( 'session.save_path' );
		$path = false !== strpos( $path, ';' ) ? substr( $path, strrpos( $path, ';' ) + 1 ) : $path;
		$path = '' !== $path ? $path : sys_get_temp_dir();
		$list = @is_dir( $path ) ? @scandir( $path ) : false; // phpcs:ignore
		if ( ! $list ) {
			return;
		}
		$found = 0;
		$first = '';
		$seen  = 0;
		foreach ( $list as $name ) {
			if ( 0 !== strpos( $name, 'sess_' ) || ++$seen > 3000 ) {
				continue;
			}
			$f = rtrim( $path, '/' ) . '/' . $name;
			if ( (int) @filemtime( $f ) < $this->sig['php2shell_ts'] ) { // phpcs:ignore
				continue;
			}
			$data = (string) @file_get_contents( $f, false, null, 0, 65536 ); // phpcs:ignore
			if ( preg_match( '/<\?php|<\?=\s*\$|\beval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i', $data ) ) {
				$found++;
				$first = $first ? $first : $name;
			}
		}
		if ( $found ) {
			$this->add( 'high', 'file', sprintf( '%d PHP session file(s) contain PHP code (e.g. %s).', $found, self::clean_text( $first ) ), 'Attackers write code into session files and then make PHP include them. Ask your host to inspect the session folder.', $path, 'sess-code' );
		}
	}

	private function truthy( $v ) {
		return in_array( strtolower( trim( (string) $v ) ), array( '1', 'on', 'yes', 'true' ), true );
	}

	/* ================================================================== */
	/* Checks: wp2shell and what attackers leave behind                    */
	/* ================================================================== */

	/** 2. WordPress version against the wp2shell ranges. */
	private function check_version() {
		$v = get_bloginfo( 'version' );
		foreach ( $this->sig['vulnerable'] as $r ) {
			if ( version_compare( $v, $r[0], '>=' ) && version_compare( $v, $r[1], '<' ) ) {
				$this->add( $r[2], 'version', "WordPress $v is vulnerable to {$r[3]}.", "Update WordPress to {$r[4]} or later now. If this site was online on this version, also check the other findings for signs of a break-in.", '', 'wp-status' );
				return;
			}
		}
		$this->add( 'info', 'version', "WordPress $v is not affected by wp2shell.", 'If the site ran WordPress 6.8–7.0.1 before updating, check the other findings for signs of a break-in.', '', 'wp-status' );
	}

	/** 3. Installed plugins. */
	private function check_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		wp_cache_delete( 'plugins', 'plugins' );
		$plugins = get_plugins();
		$dir     = wp_normalize_path( untrailingslashit( WP_PLUGIN_DIR ) );
		$self    = wp_normalize_path( untrailingslashit( WP2SS_DIR ) );
		$recent  = array();

		foreach ( $plugins as $file => $data ) {
			$slug = dirname( $file );
			$path = '.' === $slug ? "$dir/$file" : "$dir/$slug";
			if ( wp_normalize_path( $path ) === $self ) {
				continue; // Checked by check_own_folder().
			}
			$name = isset( $data['Name'] ) ? trim( $data['Name'] ) : '';

			if ( preg_match( '/^wp2shell_[0-9a-f]{4,}$/i', $slug ) || preg_match( '/(^|\/)wp2shell_[0-9a-f]{4,}\.php$/i', $file ) ) {
				$this->add( 'critical', 'plugin', "Plugin matches the wp2shell exploit's naming: $file", 'This is the webshell the public exploit uploads. Keep a copy as evidence, then delete it.', "$dir/$file" );
			}
			if ( 0 === strcasecmp( $name, 'CMSmap' ) || false !== stripos( $slug, 'cmsmap' ) ) {
				$this->add( 'critical', 'plugin', "Plugin named \"CMSmap\" is installed ($file).", 'Seen in the wild as a 150 KB webshell disguised as this security tool.', "$dir/$file" );
			}
			if ( false !== stripos( $name, 'WP Static Cache Helper' ) || preg_match( '/wp-static-cache-[0-9a-f]+\.php$/i', $file ) ) {
				$this->add( 'critical', 'plugin', "Fake \"WP Static Cache Helper\" plugin: $file", 'Known wp2shell webshell disguise.', "$dir/$file" );
			}
			if ( preg_match( '/^gg-/i', $name ) || preg_match( '/^gg-/i', $slug ) ) {
				$this->add( 'high', 'plugin', "Plugin with \"gg-\" prefix: $name ($file)", 'Matches the naming of a REST-API webshell seen after wp2shell. Inspect it.', "$dir/$file" );
			}
			if ( '.' === $slug && 'hello.php' !== $file ) {
				$this->add( 'low', 'plugin', "Single-file plugin directly in /plugins: $file", 'Not necessarily bad, but a common webshell pattern. Confirm you installed it.', "$dir/$file" );
			}

			$mtime = @filemtime( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $mtime && $mtime >= $this->sig['disclosure_ts'] ) {
				$recent[] = $name ? $name : $slug;
			}
		}

		if ( $recent ) {
			sort( $recent );
			$this->add( 'low', 'plugin', sprintf( '%d plugin(s) installed or updated since July 17, 2026: %s', count( $recent ), implode( ', ', $recent ) ), 'Normal if you or auto-updates updated them. Any you don’t recognise should be investigated.', $dir, 'plugins-recent' );
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

	/** 4. Must-use plugins run on every request and are invisible on the Plugins screen. */
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

	/** All administrator user IDs, across every site of a network — one query. */
	private function admin_ids() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$ids = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT user_id FROM {$wpdb->usermeta} WHERE meta_key LIKE %s AND meta_value LIKE %s LIMIT 1000",
				$wpdb->esc_like( $wpdb->base_prefix ) . '%capabilities',
				'%' . $wpdb->esc_like( '"administrator"' ) . '%'
			)
		);
		$ids = array_map( 'intval', (array) $ids );
		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$u = get_user_by( 'login', $login );
				if ( $u ) {
					$ids[] = (int) $u->ID;
				}
			}
		}
		$ids = array_values( array_unique( $ids ) );
		sort( $ids );
		return $ids;
	}

	/** 5. Administrators created since July 17, 2026. */
	private function check_admins() {
		global $wpdb;
		$since = gmdate( 'Y-m-d H:i:s', $this->sig['disclosure_ts'] );
		$first = $wpdb->get_var( "SELECT MIN(user_registered) FROM {$wpdb->users}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

		foreach ( $this->admin_ids() as $id ) {
			$u = get_userdata( $id );
			if ( ! $u || $u->user_registered < $since ) {
				continue;
			}
			// An admin created within an hour of the very first account is almost certainly the owner setting up.
			$at_install = $first && abs( strtotime( $u->user_registered ) - strtotime( $first ) ) < HOUR_IN_SECONDS;
			$after_php  = strtotime( $u->user_registered ) >= $this->sig['php2shell_ts'];
			$this->add(
				$at_install ? 'low' : 'high',
				'user',
				sprintf( 'Administrator "%s" (%s) was created %s UTC%s.', $u->user_login, $u->user_email, $u->user_registered, $at_install ? ', when the site was set up' : ( $after_php ? ', after PHP2Shell attacks began' : '' ) ),
				$at_install ? 'Looks like the original site admin. Ignore this if so.' : 'Attackers create admin accounts after breaking in. If you don’t recognise this one, remove it and reset every admin password.',
				'user:' . $u->ID
			);
		}
	}

	/** 6. Accounts that became administrators since the previous scan — catches backdated accounts too. */
	private function check_admin_baseline() {
		$b = get_site_option( self::BASELINE_OPTION );
		if ( ! is_array( $b ) || empty( $b['ids'] ) ) {
			return; // First scan: the baseline is saved when it finishes.
		}
		if ( empty( $b['sig'] ) || ! hash_equals( $this->baseline_sig( $b['ids'], (int) $b['at'] ), (string) $b['sig'] ) ) {
			$this->add( 'high', 'user', 'The scanner’s saved list of administrators was changed outside WordPress.', 'Someone with database access may be covering their tracks. Review every administrator under Users.', '', 'baseline-tampered' );
			return;
		}
		foreach ( array_diff( $this->admin_ids(), $b['ids'] ) as $id ) {
			$u = get_userdata( $id );
			if ( ! $u || strtotime( $u->user_registered ) >= $this->sig['disclosure_ts'] ) {
				continue; // New accounts are already reported by check_admins().
			}
			$this->add( 'high', 'user', sprintf( 'Existing account "%s" (%s, registered %s) became an administrator since the scan on %s.', $u->user_login, $u->user_email, $u->user_registered, gmdate( 'Y-m-d', (int) $b['at'] ) ), 'If you didn’t promote this user, an attacker may have — or backdated a new account to look old. Remove its admin role and reset admin passwords.', 'user:' . $u->ID );
		}
	}

	private function baseline_sig( $ids, $at ) {
		return hash_hmac( 'sha256', 'wp2ss-admins|' . implode( ',', $ids ) . '|' . $at, wp_salt( 'auth' ) );
	}

	private function save_admin_baseline() {
		try {
			$ids = $this->admin_ids();
			$at  = time();
			update_site_option( self::BASELINE_OPTION, array( 'ids' => $ids, 'at' => $at, 'sig' => $this->baseline_sig( $ids, $at ) ) );
		} catch ( Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement
			// Not fatal: the next scan simply has no baseline.
		}
	}

	/** 7. Application passwords added to admins since July 17 (quiet persistence). */
	private function check_app_passwords() {
		if ( ! class_exists( 'WP_Application_Passwords' ) ) {
			return;
		}
		foreach ( $this->admin_ids() as $id ) {
			foreach ( (array) WP_Application_Passwords::get_user_application_passwords( $id ) as $p ) {
				if ( ! empty( $p['created'] ) && $p['created'] >= $this->sig['disclosure_ts'] ) {
					$u = get_userdata( $id );
					$this->add( 'medium', 'user', sprintf( 'Application password "%s" added to admin "%s" on %s.', $p['name'], $u ? $u->user_login : $id, gmdate( 'Y-m-d', $p['created'] ) ), 'Gives API access without the login screen. Revoke it in the user’s profile if you didn’t create it.', 'user:' . $id );
				}
			}
		}
	}

	/** 8. Non-admin roles that were given admin powers. */
	private function check_roles() {
		if ( ! function_exists( 'wp_roles' ) ) {
			return;
		}
		foreach ( wp_roles()->roles as $role => $def ) {
			if ( 'administrator' === $role || empty( $def['capabilities'] ) ) {
				continue;
			}
			$bad = array_keys( array_intersect_key( array_filter( (array) $def['capabilities'] ), array_flip( $this->sig['admin_caps'] ) ) );
			if ( $bad ) {
				$this->add( 'medium', 'user', sprintf( 'The "%s" role has administrator powers: %s.', isset( $def['name'] ) ? $def['name'] : $role, implode( ', ', $bad ) ), 'Attackers sometimes give a low-level role admin powers so an ordinary-looking account can take over. Confirm a plugin you trust did this.', 'role:' . $role );
			}
		}
	}

	/** 9. REST routes registered under known webshell namespaces. */
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

	/** 10. The site root: hidden PHP, PHP auto-loaded into every request, wp-config.php. */
	private function check_root_files() {
		$abs     = wp_normalize_path( untrailingslashit( ABSPATH ) );
		$content = wp_normalize_path( untrailingslashit( WP_CONTENT_DIR ) );

		$entries = @scandir( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		foreach ( $entries ? $entries : array() as $name ) {
			$path = "$abs/$name";
			if ( '.' === $name || '..' === $name || ! is_file( $path ) || ! preg_match( $this->sig['php_ext'], $name ) ) {
				continue;
			}
			$code = (string) @file_get_contents( $path, false, null, 0, self::MAX_READ ); // phpcs:ignore
			if ( self::is_inert_data( $code ) ) {
				if ( '.' === $name[0] ) {
					$this->add( 'low', 'file', 'Hidden data file in the site root: ' . self::clean_text( $name ), 'It can’t run code: it only answers “404 Not Found” and stops, and the rest is stored data — often a plugin’s key or settings. If you don’t know what made it, check its date against when you installed plugins; quarantining it is harmless.', $path, '', sha1( $code ) );
				}
				continue;
			}
			$hit = self::match_code( $code );
			if ( self::is_installatron_worker( $code, $this->sig['installatron_keys'] ) && ( ! $hit || self::sev_rank( $hit[0] ) <= 3 ) ) {
				$this->add( 'info', 'file', 'Installatron Worker: ' . self::clean_text( $name ) . ' (site root)', 'A temporary script from Installatron, the one-click installer many hosts use (IONOS included). It only runs commands digitally signed by Installatron, and deletes itself after a while. If your host doesn’t use Installatron, delete it.', $path, 'installatron', sha1( $code ) );
				continue;
			}
			if ( '.' === $name[0] ) {
				$this->add( 'high', 'file', 'Hidden PHP file in the site root: ' . self::clean_text( $name ), 'Hidden PHP files next to WordPress are a classic backdoor. Open it and confirm what it is.', $path );
			}
			if ( $hit ) {
				$this->add( $hit[0], 'code', $hit[1] . ': ' . self::clean_text( $name ) . ' (site root)', $hit[2], $path, '', sha1( $code ) );
			}
		}

		// auto_prepend_file / auto_append_file make PHP run a file on every request.
		$cfg = array( "$abs/.user.ini", "$abs/.htaccess", "$abs/php.ini", "$content/.user.ini", "$content/.htaccess", "$content/uploads/.user.ini", "$content/uploads/.htaccess" );
		foreach ( array_unique( $cfg ) as $f ) {
			$txt = @is_file( $f ) ? @file_get_contents( $f, false, null, 0, 262144 ) : false; // phpcs:ignore
			if ( ! $txt || ! preg_match_all( $this->sig['auto_prepend'], $txt, $m, PREG_SET_ORDER ) ) {
				continue;
			}
			foreach ( $m as $hit ) {
				if ( ! preg_match( $this->sig['auto_prepend_allow'], $hit[2] ) ) {
					$this->add( 'high', 'file', sprintf( '%s makes PHP run "%s" before every page (%s).', basename( $f ), self::clean_text( $hit[2] ), $hit[1] ), 'A favourite way to hide a backdoor. Unless a security plugin you use set this up, remove the line and inspect the file it points to.', wp_normalize_path( $f ) );
				}
			}
		}

		// wp-config.php: code signatures, and recent changes.
		$config = file_exists( "$abs/wp-config.php" ) ? "$abs/wp-config.php" : ( file_exists( dirname( $abs ) . '/wp-config.php' ) ? dirname( $abs ) . '/wp-config.php' : '' );
		if ( $config ) {
			$code = (string) @file_get_contents( $config, false, null, 0, self::MAX_READ ); // phpcs:ignore
			$hit  = self::match_code( $code );
			if ( $hit ) {
				$this->add( $hit[0], 'code', $hit[1] . ': wp-config.php', $hit[2], $config, '', sha1( $code ) );
			}
			$m = @filemtime( $config ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $m && $m >= $this->sig['disclosure_ts'] ) {
				$this->add( 'low', 'file', 'wp-config.php was changed on ' . gmdate( 'Y-m-d', $m ) . '.', 'Normal if you, your host or a plugin edited it (for example a cache or security plugin). If not, compare it with a backup.', $config, 'wp-config-mtime', sha1( $code ) );
			}
		}
	}

	/**
	 * 11. This plugin's own files. With a release manifest (shipped in every
	 * release zip and published on GitHub), every file is hash-checked; without
	 * one (a source install), unexpected PHP files are still flagged.
	 */
	private function check_own_folder() {
		$self     = wp_normalize_path( untrailingslashit( WP2SS_DIR ) );
		$manifest = $this->own_manifest();

		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $self, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::LEAVES_ONLY,
			RecursiveIteratorIterator::CATCH_GET_CHILD
		);
		$seen = array();
		foreach ( $it as $f ) {
			$rel          = ltrim( substr( wp_normalize_path( $f->getPathname() ), strlen( $self ) ), '/' );
			$seen[ $rel ] = true;
			if ( $manifest ) {
				if ( isset( $manifest['files'][ $rel ] ) ) {
					if ( ! hash_equals( $manifest['files'][ $rel ], (string) @hash_file( 'sha256', $f->getPathname() ) ) ) { // phpcs:ignore
						$this->add( 'critical', 'file', "A file of this scanner plugin has been modified: $rel", 'Attackers sometimes edit security plugins to blind them. Delete this plugin and reinstall it from the official release, then scan again.', $self . '/' . $rel );
					}
				} elseif ( 'manifest.json' !== $rel && preg_match( $this->sig['php_ext'], $rel ) ) {
					$this->add( 'high', 'file', 'Unexpected PHP file inside this scanner’s own folder: ' . self::clean_text( $rel ), 'This plugin doesn’t ship that file. Attackers sometimes hide in security plugins. Reinstall the plugin from the official release.', $self . '/' . $rel );
				}
			} elseif ( preg_match( $this->sig['php_ext'], $rel ) && ! in_array( $rel, self::OWN_PHP, true ) ) {
				$this->add( 'high', 'file', 'Unexpected PHP file inside this scanner’s own folder: ' . self::clean_text( $rel ), 'This plugin doesn’t ship that file. Attackers sometimes hide in security plugins. Reinstall the plugin from the official release.', $self . '/' . $rel );
			}
		}
		if ( $manifest ) {
			foreach ( array_keys( $manifest['files'] ) as $rel ) {
				if ( ! isset( $seen[ $rel ] ) && preg_match( $this->sig['php_ext'], $rel ) ) {
					$this->add( 'high', 'file', "A file of this scanner plugin is missing: $rel", 'Reinstall the plugin from the official release.', $self . '/' . $rel );
				}
			}
		}
	}

	/** The release manifest to trust: GitHub's copy when reachable (cached), else the local one. */
	private function own_manifest() {
		$local_raw = @file_get_contents( WP2SS_DIR . 'manifest.json' ); // phpcs:ignore
		$local     = $local_raw ? json_decode( $local_raw, true ) : null;
		if ( ! is_array( $local ) || empty( $local['files'] ) ) {
			return null;
		}
		if ( ! defined( 'WP2SS_DISABLE_UPDATER' ) || ! WP2SS_DISABLE_UPDATER ) {
			$key    = 'wp2ss_manifest_' . WP2SS_VERSION;
			$remote = get_site_transient( $key );
			if ( false === $remote ) {
				$res    = wp_remote_get( 'https://github.com/' . WP2SS_Updater::REPO . '/releases/download/v' . WP2SS_VERSION . '/manifest.json', array( 'timeout' => 5 ) );
				$remote = ( ! is_wp_error( $res ) && 200 === wp_remote_retrieve_response_code( $res ) ) ? json_decode( wp_remote_retrieve_body( $res ), true ) : array();
				set_site_transient( $key, is_array( $remote ) ? $remote : array(), is_array( $remote ) && $remote ? WEEK_IN_SECONDS : 6 * HOUR_IN_SECONDS );
			}
			if ( is_array( $remote ) && ! empty( $remote['files'] ) ) {
				if ( $remote['files'] != $local['files'] ) { // phpcs:ignore WordPress.PHP.StrictComparisons
					$this->add( 'critical', 'file', 'This scanner’s file list (manifest.json) doesn’t match the official release.', 'Its files may have been tampered with. Delete and reinstall the plugin from the official release.', WP2SS_DIR . 'manifest.json' );
				}
				return $remote;
			}
		}
		return $local;
	}

	/**
	 * 12. Walk the site's content folders depth-first, keeping only one open
	 * folder per level. The place is saved as (folder, entries read) per level,
	 * so a slice can stop anywhere — even in the middle of a folder with a
	 * million files — and the saved state stays small.
	 *
	 * @return bool True when the walk is complete.
	 */
	private function walk_files() {
		$handles = array();
		$done    = false;

		while ( ! $this->out_of_time() ) {
			// Start the next root folder when the current one is finished.
			if ( ! $this->s['frames'] ) {
				if ( $this->s['root'] ) {
					$this->s['roots_done'] = ( isset( $this->s['roots_done'] ) ? $this->s['roots_done'] : 0 ) + 1;
					$this->s['root']       = null;
				}
				if ( ! $this->s['roots'] ) {
					$done = true;
					break;
				}
				list( $enc, $label ) = array_shift( $this->s['roots'] );
				$path                = self::dec( $enc );
				$list                = @scandir( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$this->s['root']     = array( 'path' => $enc, 'label' => $label, 'count' => $list ? count( $list ) : 0 );
				$this->s['frames'][] = array( $enc, 0 );
				unset( $list );
			}

			$depth = count( $this->s['frames'] ) - 1;
			$dir   = self::dec( $this->s['frames'][ $depth ][0] );

			if ( ! isset( $handles[ $depth ] ) ) {
				$dh = @opendir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( ! $dh ) {
					$this->s['stats']['unreadable']++;
					array_pop( $this->s['frames'] );
					continue;
				}
				for ( $i = 0; $i < $this->s['frames'][ $depth ][1] && false !== readdir( $dh ); $i++ ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement
					// Skip what an earlier slice already read.
				}
				$handles[ $depth ] = $dh;
			}

			$name = readdir( $handles[ $depth ] );
			if ( false === $name ) {
				closedir( $handles[ $depth ] );
				unset( $handles[ $depth ] );
				array_pop( $this->s['frames'] );
				$this->s['stats']['dirs']++;
				continue;
			}
			$this->s['frames'][ $depth ][1]++;
			if ( '.' === $name || '..' === $name ) {
				continue;
			}

			$path = $dir . '/' . $name;
			$rel  = $this->rel_path( $path );

			if ( is_dir( $path ) ) {
				if ( is_link( $path ) && ! $this->may_follow_link( $path, $dir ) ) {
					continue;
				}
				if ( 0 === strpos( $name, 'wp2ss-quarantine-' ) && wp_normalize_path( $path ) === WP2SS_Fixes::qdir() ) {
					continue; // Our own quarantine: everything in it has already been dealt with.
				}
				if ( preg_match( '/^wp2shell_[0-9a-f]{4,}$/i', $name ) && 0 !== strpos( $rel, 'wp-content/plugins/' ) ) {
					$this->add( 'critical', 'file', 'wp2shell staging folder: ' . self::clean_text( $rel ), 'Left over from the exploit’s plugin upload.', $path );
				}
				$this->s['frames'][] = array( self::enc( $path ), 0 );
				continue;
			}

			$this->s['stats']['files']++;
			try {
				$this->check_file( $path, $rel, $name );
			} catch ( Throwable $e ) {
				$this->s['stats']['unreadable']++;
			}
		}

		foreach ( $handles as $dh ) {
			closedir( $dh );
		}
		return $done;
	}

	/** Path as shown in findings, e.g. "wp-content/uploads/2026/10/x.php". */
	private function rel_path( $path ) {
		$root = self::dec( $this->s['root']['path'] );
		return $this->s['root']['label'] . substr( $path, strlen( $root ) );
	}

	/**
	 * Symlinked folders (common for plugins and uploads on some hosts) are
	 * followed once each, unless they point back up the tree (a loop).
	 */
	private function may_follow_link( $path, $parent ) {
		$real        = realpath( $path );
		$parent_real = realpath( $parent );
		if ( ! $real || ! $parent_real || count( $this->s['followed'] ) >= self::MAX_LINKS
			|| in_array( self::enc( $real ), $this->s['followed'], true )
			|| 0 === strpos( wp_normalize_path( $parent_real ) . '/', wp_normalize_path( $real ) . '/' ) ) {
			$this->s['stats']['links']++;
			return false;
		}
		$this->s['followed'][] = self::enc( $real );
		return true;
	}

	private function check_file( $path, $rel, $name ) {
		$parts  = explode( '/', $rel );
		$top    = isset( $parts[1] ) ? $parts[1] : '';            // e.g. "uploads" in wp-content/uploads/…
		$in_cr  = 2 === count( $parts );                            // Directly inside wp-content.
		$sub    = (string) substr( $rel, strlen( 'wp-content/' ) ); // Path below wp-content.
		$show   = self::clean_text( $rel );
		$data   = in_array( $top, $this->sig['data_dirs'], true );
		$is_php = (bool) preg_match( $this->sig['php_ext'], $name );

		if ( 0 === stripos( $name, 'temp-write-test-' ) ) {
			// WordPress itself makes these (temp-write-test-<uniqid>) when it checks it can write files,
			// and leaves them behind if deleting fails. The uniqid starts with the time it was made.
			if ( preg_match( '/^temp-write-test-([0-9a-f]{8})[0-9a-f]{5}\d-\d{8}$/i', $name, $wt ) ) {
				$made = (int) hexdec( $wt[1] );
				if ( $made < $this->sig['disclosure_ts'] ) {
					$this->add( 'low', 'file', 'WordPress write-test file left over from ' . gmdate( 'Y-m-d', $made ) . ": $show", 'WordPress creates these when it checks it can write files, and sometimes fails to delete them. This one predates the wp2shell attacks. Safe to delete.', $path );
				} else {
					$this->add( 'medium', 'file', 'Write-test file created ' . gmdate( 'Y-m-d', $made ) . ", after wp2shell attacks began: $show", 'WordPress itself makes these when updating, but the public wp2shell exploit does the same. If nobody updated the site around then, check the other findings.', $path );
				}
			} else {
				$this->add( 'high', 'file', "Write-test file: $show", 'Named like WordPress’s write test, but not made by WordPress. The public wp2shell exploit creates these to check it can write to the site.', $path );
			}
		}
		if ( preg_match( '/^wp2shell_[0-9a-f]{4,}\.zip$/i', $name ) ) {
			$this->add( 'critical', 'file', "wp2shell plugin archive: $show", 'The exploit’s uploaded payload.', $path );
		}
		if ( ( '.htaccess' === $name || '.user.ini' === $name ) && $data ) {
			$ht = @file_get_contents( $path, false, null, 0, 65536 ); // phpcs:ignore
			if ( $ht && '.htaccess' === $name && preg_match( $this->sig['htaccess_php'], $ht ) ) {
				$this->add( 'high', 'file', "Upload-folder .htaccess makes PHP executable: $show", 'Attackers add this so uploaded PHP will run. Remove those lines.', $path );
			}
			if ( $ht && preg_match( $this->sig['auto_prepend'], $ht, $m ) && ! preg_match( $this->sig['auto_prepend_allow'], $m[2] ) ) {
				$this->add( 'high', 'file', sprintf( '%s makes PHP run "%s" before every page: %s', $name, self::clean_text( $m[2] ), $show ), 'A favourite way to hide a backdoor. Remove the line and inspect the file it points to.', $path );
			}
		}

		// Images in uploads that carry PHP code.
		if ( 'uploads' === $top && ! $is_php && preg_match( $this->sig['image_ext'], $name ) ) {
			$head = @file_get_contents( $path, false, null, 0, self::IMAGE_READ ); // phpcs:ignore
			if ( $head && false !== stripos( $head, '<?php' ) ) {
				$this->add( 'high', 'file', "Image file contains PHP code: $show", 'A known trick to smuggle a backdoor in as a picture. Delete it unless you know what it is.', $path, '', (string) @sha1_file( $path ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
			return;
		}

		if ( ! $is_php ) {
			return;
		}
		$this->s['stats']['php_files']++;

		$size = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$code = false;
		if ( $size > 0 && $size <= self::MAX_READ ) {
			$code = @file_get_contents( $path ); // phpcs:ignore
			$sha1 = is_string( $code ) ? sha1( $code ) : '';
		} else {
			$sha1 = (string) @sha1_file( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $size > self::MAX_READ ) {
				// Too big to read whole: check the start and the end, where injected code usually sits.
				$this->s['stats']['large']++;
				$code = $this->read_edges( $path, $size );
			}
		}

		if ( $sha1 && isset( $this->sig['sha1'][ $sha1 ] ) ) {
			$this->add( 'critical', 'hash', "Known webshell: $show", "File hash $sha1 matches a published indicator ({$this->sig['sha1'][ $sha1 ]}).", $path, '', $sha1 );
			return;
		}

		$mtime = (int) @filemtime( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$whole = is_string( $code ) && $size <= self::MAX_READ;

		// PHP inside data folders, or loose in wp-content itself.
		if ( ( $data || $in_cr ) && ! ( $whole && self::is_empty_php( $code ) ) && ! preg_match( $this->sig['data_allow'], $sub ) && ! ( $in_cr && in_array( $name, $this->sig['content_root_allow'], true ) ) ) {
			$guarded = $whole && ( self::is_guarded_php( $code ) || self::is_inert_data( $code ) );
			$recent  = $mtime >= $this->sig['disclosure_ts'];
			$sev     = $guarded ? 'low' : ( $recent ? 'high' : 'medium' );
			$where   = $in_cr ? 'directly in wp-content' : 'in a data folder';
			$this->add(
				$sev,
				'file',
				"PHP file $where" . ( $recent ? ' (changed ' . gmdate( 'Y-m-d', $mtime ) . ')' : '' ) . ": $show",
				'cache' === $top ? 'Attackers have written webshells into wp-content/cache/. Open it and confirm what it is.' : 'PHP doesn’t normally live here. Open it and confirm what it is.',
				$path,
				'',
				$sha1
			);
		}

		if ( '.' === $name[0] ) {
			$this->add( $whole && self::is_inert_data( $code ) ? 'low' : 'medium', 'file', "Hidden PHP file: $show", 'Hidden PHP files are a common way to tuck away backdoors.' . ( $whole && self::is_inert_data( $code ) ? ' This one can’t run code (it only answers 404 and stops), so it’s probably a plugin’s data file.' : '' ), $path, '', $sha1 );
		}

		if ( is_string( $code ) && '' !== $code && ! ( $whole && self::is_inert_data( $code ) ) ) {
			$hit = self::match_code( $code );
			if ( $hit ) {
				$this->add( $hit[0], 'code', "{$hit[1]}: $show", $hit[2], $path, '', $sha1 );
			}
		}

		if ( 'themes' === $top && $mtime >= $this->sig['disclosure_ts'] && isset( $parts[3] ) ) {
			$theme = $parts[2];
			if ( ! isset( $this->s['themes'][ $theme ] ) ) {
				$this->s['themes'][ $theme ] = array( 'n' => 0, 'files' => array() );
			}
			$this->s['themes'][ $theme ]['n']++;
			if ( count( $this->s['themes'][ $theme ]['files'] ) < 5 ) {
				$this->s['themes'][ $theme ]['files'][] = $show;
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

	private function flush_theme_changes() {
		foreach ( $this->s['themes'] as $theme => $t ) {
			$this->add( 'low', 'file', sprintf( 'Theme "%s": %d PHP file(s) changed since July 17, 2026.', self::clean_text( $theme ), $t['n'] ), 'Normal after a theme update or your own edits. Otherwise inspect: ' . implode( ', ', $t['files'] ) . ( $t['n'] > 5 ? ' …' : '' ), wp_normalize_path( WP_CONTENT_DIR . '/themes/' . $theme ), 'theme-recent' );
		}
		$this->s['themes'] = array();
	}

	/**
	 * 13. Core files vs wordpress.org checksums. Resumable.
	 *
	 * @return bool True when finished.
	 */
	private function check_core() {
		$abs = wp_normalize_path( ABSPATH );

		if ( null === $this->s['core'] ) {
			$sums = $this->core_sums( true );
			if ( null === $sums ) {
				$this->add( 'info', 'core', 'Couldn’t get core checksums from wordpress.org, so core files weren’t verified.', 'Your server may block outbound requests. Your host can run `wp core verify-checksums` for you.', '', 'core-unverified' );
				return true;
			}
			$this->s['core'] = array( 'pos' => 0, 'total' => count( $sums ), 'bad' => array(), 'extra' => false );
		}

		$sums = $this->core_sums( false );
		if ( null === $sums ) {
			return true; // Cache vanished mid-scan: skip quietly rather than refetch.
		}
		$keys = array_keys( $sums );
		$c    = &$this->s['core'];

		while ( $c['pos'] < $c['total'] ) {
			$file = $keys[ $c['pos'] ];
			$c['pos']++;
			if ( 0 !== strpos( $file, 'wp-content/' ) ) {
				$p = $abs . $file;
				if ( is_file( $p ) && @md5_file( $p ) !== $sums[ $file ] ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
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
				$this->add( 'high', 'core', ( count( $c['bad'] ) - 25 ) . ' more modified core files.', 'Reinstall WordPress core.', '', 'core-more' );
			}

			// Files WordPress itself deletes on upgrade but FTP-style updates leave behind.
			$old = array();
			if ( is_readable( ABSPATH . 'wp-admin/includes/update-core.php' ) ) {
				global $_old_files;
				require_once ABSPATH . 'wp-admin/includes/update-core.php';
				$old = is_array( $_old_files ) ? array_flip( $_old_files ) : array();
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
					if ( ! preg_match( $this->sig['php_ext'], $f->getFilename() ) ) {
						continue;
					}
					$rel = substr( wp_normalize_path( $f->getPathname() ), strlen( $abs ) );
					if ( isset( $sums[ $rel ] ) ) {
						continue;
					}
					if ( isset( $old[ $rel ] ) ) {
						$this->add( 'low', 'core', 'Leftover file from an older WordPress version: ' . self::clean_text( $rel ), 'Usually harmless (left by a manual update). Reinstalling core removes it.', $abs . $rel );
					} elseif ( isset( $this->sig['core_removed'][ $rel ] ) ) {
						$sha1 = (string) @sha1_file( $f->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
						if ( in_array( $sha1, $this->sig['core_removed'][ $rel ], true ) ) {
							$this->add( 'low', 'core', 'Leftover file from WordPress 7.0: ' . self::clean_text( $rel ), 'Part of WordPress 7.0’s real-time collaboration feature, which later versions removed; updates don’t delete old files. It matches the official file. Harmless, and safe to delete.', $abs . $rel, '', $sha1 );
						} else {
							$this->add( 'medium', 'core', 'File named like a WordPress 7.0 leftover, but its contents don’t match any official version: ' . self::clean_text( $rel ), 'It may be a development copy — or a backdoor using a real file’s name. Open it and check.', $abs . $rel, '', $sha1 );
						}
					} else {
						$this->add( 'high', 'core', 'Unknown PHP file in a core folder: ' . self::clean_text( $rel ), 'Not part of WordPress — very likely a backdoor.', $abs . $rel );
					}
				}
			}

			$entries = @scandir( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			foreach ( $entries ? $entries : array() as $b ) {
				if ( '.' !== $b[0] && is_file( $abs . $b ) && preg_match( $this->sig['php_ext'], $b ) && ! isset( $sums[ $b ] ) && ! in_array( $b, $this->sig['root_allow'], true ) ) {
					$head = (string) @file_get_contents( $abs . $b, false, null, 0, self::MAX_READ ); // phpcs:ignore
					if ( self::is_inert_data( $head ) || self::is_installatron_worker( $head, $this->sig['installatron_keys'] ) ) {
						continue; // Reported (or explained) by the site-root check.
					}
					$this->add( 'medium', 'core', 'Unknown PHP file in the site root: ' . self::clean_text( $b ), 'Confirm you or your host put it there.', $abs . $b );
				}
			}
			$c['extra'] = true;
			$c['bad']   = array();
		}
		return true;
	}

	/**
	 * Core checksums for this version, cached for a day. Fetching can hang on
	 * hosts that silently drop outbound traffic, so it's attempted at most
	 * MAX_TRIES times per scan. Null if unavailable.
	 */
	private function core_sums( $may_fetch ) {
		static $mem = null;
		if ( null !== $mem ) {
			return $mem;
		}
		$v      = get_bloginfo( 'version' );
		$locale = get_locale();
		$key    = 'wp2ss_core_' . md5( $v . '|' . $locale );
		$sums   = get_site_transient( $key );
		if ( ! is_array( $sums ) ) {
			if ( ! $may_fetch || ! $this->attempt( 'core_fetch' ) ) {
				return null;
			}
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

	/* ================================================================== */
	/* Logs                                                                */
	/* ================================================================== */

	/** Logs to read: the access log from settings, PHP's error log, and WordPress's debug.log. */
	private function log_list() {
		$list = array();
		if ( ! empty( $this->s['args']['log'] ) ) {
			$list[] = array( (string) $this->s['args']['log'], 'access', true );
		}
		$errs = array();
		if ( ! empty( $this->s['args']['error_log'] ) ) {
			$errs[] = array( (string) $this->s['args']['error_log'], true );
		}
		$el = isset( $this->s['env']['error_log'] ) ? (string) $this->s['env']['error_log'] : '';
		if ( $el && ( '/' === $el[0] || preg_match( '#^[A-Za-z]:[\\\\/]#', $el ) ) ) {
			$errs[] = array( $el, false );
		}
		$debug = ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) ) ? WP_DEBUG_LOG : WP_CONTENT_DIR . '/debug.log';
		$errs[] = array( $debug, false );

		$seen = array();
		foreach ( $errs as $e ) {
			$real = @realpath( $e[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$k    = $real ? $real : $e[0];
			if ( ! isset( $seen[ $k ] ) ) {
				$seen[ $k ] = true;
				$list[]     = array( $e[0], 'error', $e[1] );
			}
		}
		return $list;
	}

	/**
	 * 14. Read each log once, resumable by byte offset.
	 *
	 * @return bool True when all logs are done.
	 */
	private function scan_logs() {
		if ( null === $this->s['logs'] ) {
			$this->s['logs'] = array( 'list' => $this->log_list(), 'i' => 0, 'pos' => 0, 'c' => null );
		}
		$L = &$this->s['logs'];

		while ( $L['i'] < count( $L['list'] ) ) {
			list( $path, $kind, $explicit ) = $L['list'][ $L['i'] ];
			if ( null === $L['c'] ) {
				$L['c'] = 'access' === $kind
					? array( 'batch_ok' => 0, 'ua' => 0, 'ip' => 0, 'upload' => 0, 'users' => 0, 'post_fail' => array(), 'sample' => array() )
					: array( 'hits' => array(), 'oom_any' => 0, 'sample' => array() );
				$L['c']['p2s'] = 0;
				$L['c']['p2s_ip'] = 0;
			}

			if ( ! @is_file( $path ) || ! @is_readable( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( $explicit ) {
					$this->add( 'info', 'log', 'Log file not readable: ' . self::clean_text( $path ), 'Check the path, and that PHP is allowed to read it (open_basedir / permissions).', $path, 'unreadable' );
				}
				$this->next_log();
				continue;
			}

			$done = $this->read_log( $path, $kind );
			if ( ! $done ) {
				return false;
			}
			'access' === $kind ? $this->report_access_log( $path ) : $this->report_error_log( $path );
			$this->next_log();
		}
		return true;
	}

	private function next_log() {
		$this->s['logs']['i']++;
		$this->s['logs']['pos'] = 0;
		$this->s['logs']['c']   = null;
	}

	/** @return bool True at end of file. */
	private function read_log( $path, $kind ) {
		$L  = &$this->s['logs'];
		$c  = &$L['c'];
		$gz = (bool) preg_match( '/\.gz$/i', $path );
		$fh = $gz ? @gzopen( $path, 'rb' ) : @fopen( $path, 'rb' ); // phpcs:ignore
		if ( ! $fh ) {
			return true;
		}
		if ( ! $gz ) {
			fseek( $fh, $L['pos'] ); // Compressed logs are read in one go: seeking in them means re-reading from the start.
		}

		$cut     = $this->sig['php2shell_ts'];
		$mt      = (int) @filemtime( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$n       = 0;
		$eof     = false;
		$ua      = $this->sig['user_agents'];
		$ips     = array_flip( $this->sig['ips'] );
		$fail    = array_flip( $this->sig['post_fail_status'] );
		$err_sig = $this->sig['php_error_log'];
		$p2s     = $this->sig['php2shell_log'];
		$p2s_ips = array_flip( $this->sig['php2shell_ips'] );

		while ( true ) {
			$line = $gz ? gzgets( $fh, 16384 ) : fgets( $fh, 16384 );
			if ( false === $line ) {
				$eof = true;
				break;
			}

			// PHP2Shell exploit tools, canary and payload — in any log.
			if ( preg_match( $p2s, $line ) ) {
				$t = $this->line_time( $line );
				if ( $t >= $cut || 0 === $t ) {
					$c['p2s']++;
					if ( count( $c['sample'] ) < 3 ) {
						$c['sample'][] = self::clean_text( trim( substr( $line, 0, 240 ) ) );
					}
				}
			}

			if ( 'access' === $kind ) {
				$dec = rawurldecode( $line );
				$hit = false;
				if ( preg_match( '#(rest_route=/?batch/v1|/wp-json/batch/v1)#i', $dec ) && preg_match( '#"\s+(200|207)\s#', $line ) ) {
					$c['batch_ok']++;
					$hit = true;
				}
				if ( preg_match( $ua, $line ) ) {
					$c['ua']++;
					$hit = true;
				}
				$ip = (string) strtok( $line, " \t" );
				if ( isset( $ips[ $ip ] ) ) {
					$c['ip']++;
					$hit = true;
				}
				if ( isset( $p2s_ips[ $ip ] ) && $this->line_time( $line ) >= $cut ) {
					$c['p2s_ip']++;
				}
				if ( false !== strpos( $dec, 'action=upload-plugin' ) ) {
					$c['upload']++;
				}
				if ( false !== strpos( $dec, 'users?context=edit' ) ) {
					$c['users']++;
				}
				// PHP2Shell: bursts of POSTs that crashed PHP, since attacks began.
				if ( false !== strpos( $line, '"POST ' ) && preg_match( '#"\s+(\d{3})\s#', $line, $sm ) && isset( $fail[ $sm[1] ] ) ) {
					$t = $this->line_time( $line );
					if ( $t >= $cut && ( isset( $c['post_fail'][ $ip ] ) || count( $c['post_fail'] ) < 5000 ) ) {
						$c['post_fail'][ $ip ] = ( isset( $c['post_fail'][ $ip ] ) ? $c['post_fail'][ $ip ] : 0 ) + 1;
					}
				}
				if ( $hit && count( $c['sample'] ) < 3 ) {
					$c['sample'][] = self::clean_text( trim( substr( $line, 0, 240 ) ) );
				}
			} else {
				if ( false !== stripos( $line, 'Allowed memory size' ) || false !== stripos( $line, 'session object' ) || false !== stripos( $line, 'signal 11' ) || false !== stripos( $line, 'SIGSEGV' ) || false !== stripos( $line, 'segfault' ) || false !== stripos( $line, 'heap corrupted' ) || false !== stripos( $line, 'Maximum execution time' ) ) {
					$t = $this->line_time( $line );
					if ( $t >= $cut || ( 0 === $t && $mt >= $cut ) ) {
						if ( false !== stripos( $line, 'Allowed memory size' ) ) {
							$c['oom_any']++;
						}
						foreach ( $err_sig as $s ) {
							if ( preg_match( $s[2], $line ) ) {
								$c['hits'][ $s[0] ] = ( isset( $c['hits'][ $s[0] ] ) ? $c['hits'][ $s[0] ] : 0 ) + 1;
								if ( count( $c['sample'] ) < 3 ) {
									$c['sample'][] = self::clean_text( trim( substr( $line, 0, 240 ) ) );
								}
							}
						}
					}
				}
			}

			if ( ! $gz && 0 === ( ++$n % 5000 ) && $this->out_of_time() ) {
				break;
			}
		}
		$L['pos'] = $gz ? 0 : ftell( $fh );
		$gz ? gzclose( $fh ) : fclose( $fh );
		return $eof;
	}

	/** Timestamp of a log line (Apache/nginx access, PHP error log, Apache error log, ISO). 0 if none found. */
	private function line_time( $line ) {
		static $mon = array( 'jan' => 1, 'feb' => 2, 'mar' => 3, 'apr' => 4, 'may' => 5, 'jun' => 6, 'jul' => 7, 'aug' => 8, 'sep' => 9, 'oct' => 10, 'nov' => 11, 'dec' => 12 );
		if ( preg_match( '#\[(\d{1,2})[/-](\w{3})[/-](\d{4})[: ](\d{2}):(\d{2}):(\d{2})#', $line, $m ) && isset( $mon[ strtolower( $m[2] ) ] ) ) {
			return gmmktime( (int) $m[4], (int) $m[5], (int) $m[6], $mon[ strtolower( $m[2] ) ], (int) $m[1], (int) $m[3] );
		}
		if ( preg_match( '#\[\w{3} (\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})\]#', $line, $m ) && isset( $mon[ strtolower( $m[1] ) ] ) ) {
			return gmmktime( (int) $m[3], (int) $m[4], (int) $m[5], $mon[ strtolower( $m[1] ) ], (int) $m[2], (int) $m[6] );
		}
		if ( preg_match( '#(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})#', $line, $m ) ) {
			return gmmktime( (int) $m[4], (int) $m[5], (int) $m[6], (int) $m[2], (int) $m[3], (int) $m[1] );
		}
		return 0;
	}

	private function report_access_log( $path ) {
		$c      = $this->s['logs']['c'];
		$name   = self::clean_text( $path );
		$sample = $c['sample'] ? ' Example: ' . implode( ' | ', $c['sample'] ) : '';

		if ( $c['batch_ok'] ) {
			$this->add( 'critical', 'log', "{$c['batch_ok']} successful (200/207) requests to the WordPress batch API.", 'A high-confidence sign the wp2shell exploit worked.' . $sample, $path, 'batch-ok' );
		}
		if ( $c['ua'] ) {
			$this->add( 'high', 'log', "{$c['ua']} requests from wp2shell exploit tools (user-agent).", 'The site was targeted. Check whether anything else shows it succeeded.' . ( $c['batch_ok'] ? '' : $sample ), $path, 'ua' );
		}
		if ( $c['ip'] ) {
			$this->add( 'high', 'log', "{$c['ip']} requests from published wp2shell attacker IPs.", '', $path, 'ip' );
		}
		if ( $c['upload'] ) {
			$this->add( 'medium', 'log', "{$c['upload']} plugin-upload requests.", 'Match these against uploads you made yourself.', $path, 'upload' );
		}
		if ( $c['users'] ) {
			$this->add( 'medium', 'log', "{$c['users']} admin user-enumeration requests (users?context=edit).", 'Seen as wp2shell follow-up activity.', $path, 'users' );
		}

		arsort( $c['post_fail'] );
		$burst = array();
		foreach ( $c['post_fail'] as $ip => $n ) {
			if ( $n >= $this->sig['post_fail_burst'] && count( $burst ) < 5 ) {
				$burst[] = "$ip ($n)";
			}
		}
		if ( $burst ) {
			$this->add( 'medium', 'log', 'Bursts of POST requests that crashed PHP (HTTP 500/502) since October 17, 2026, from: ' . implode( ', ', $burst ) . '.', 'PHP2Shell attacks send repeated large POSTs that make PHP run out of memory. This is a lead, not proof — check what those addresses were doing.', $path, 'post-fail' );
		}

		$this->report_p2s( $c, $path, $sample );
		if ( $c['p2s_ip'] ) {
			$this->add( 'medium', 'log', "{$c['p2s_ip']} requests since October 17, 2026 from addresses seen attempting PHP2Shell.", 'These are anonymising services also used by ordinary people, so check what the requests did rather than assuming the worst.', $path, 'p2s-ip' );
		}

		if ( ! $c['batch_ok'] && ! $c['ua'] && ! $c['ip'] && ! $burst && ! $c['p2s'] && ! $c['p2s_ip'] ) {
			$this->add( 'info', 'log', "No attack traces found in $name.", 'Logs rotate — older activity may be in archived logs (.gz files work too).', $path, 'clean' );
		}
	}

	private function report_p2s( $c, $path, $sample ) {
		if ( ! empty( $c['p2s'] ) ) {
			$this->add( 'high', 'log', "{$c['p2s']} log lines show PHP2Shell exploit tools or their payload (scanner user agents, the JACKALPOC test, or the /tmp/nfs download).", 'Someone ran a PHP2Shell exploit against this server. If PHP wasn’t patched at the time, treat the server as compromised: tell your host, update PHP, and change every password and key.' . $sample, $path, 'p2s-tools' );
		}
	}

	private function report_error_log( $path ) {
		$c      = $this->s['logs']['c'];
		$sample = $c['sample'] ? ' Example: ' . implode( ' | ', $c['sample'] ) : '';
		list( $php_status ) = WP2SS_Env::php2shell_status_env( $this->s['env'], $this->sig );
		$patched = in_array( $php_status, array( 'fixed', 'newer' ), true );
		$this->report_p2s( $c, $path, $sample );
		foreach ( $this->sig['php_error_log'] as $s ) {
			$n = isset( $c['hits'][ $s[0] ] ) ? $c['hits'][ $s[0] ] : 0;
			if ( ! $n ) {
				continue;
			}
			// The patched PHP logs this one itself (php-src #24493): only meaningful alongside other signs.
			if ( 'session_decode' === $s[0] && $patched && empty( $c['hits']['oom_unknown'] ) ) {
				$this->add( 'info', 'log', sprintf( '%d "Failed to decode session object" errors since October 17, 2026.', $n ), 'On patched PHP this is a known, harmless side-effect of the fix (php-src issue #24493).', $path, 'err-session-patched' );
				continue;
			}
			$sev = ( 'high' === $s[1] || $n >= $this->sig['php_error_burst'] ) ? 'high' : $s[1];
			$this->add( $sev, 'log', sprintf( '%d %s in the PHP error log since October 17, 2026.', $n, $s[3] ), 'This is what PHP2Shell exploitation attempts look like in the logs. ' . ( 'high' === $sev ? 'Treat the server as possibly compromised: check the other findings, update PHP, and change passwords and keys.' : 'A few can be normal; a burst is a red flag.' ) . $sample, $path, 'err-' . $s[0] );
		}
		// With memory_limit=-1 (the stopgap), out-of-memory errors should be impossible.
		if ( $c['oom_any'] && '-1' === (string) $this->s['env']['memory_limit'] ) {
			$this->add( 'high', 'log', sprintf( '%d out-of-memory errors since October 17, 2026 even though memory_limit is -1.', $c['oom_any'] ), 'With memory_limit=-1 these errors should not happen, which points to an exploitation attempt.' . $sample, $path, 'err-oom-nolimit' );
		}
	}

	/* ================================================================== */
	/* Findings                                                            */
	/* ================================================================== */

	/**
	 * Build a finding. Its ID comes from the type, the location and a stable
	 * key (or the message with numbers removed), so counts and dates changing
	 * between scans don't resurrect a finding you ignored.
	 */
	private function make( $severity, $type, $message, $advice = '', $location = '', $key = '', $sha1 = '' ) {
		$message  = self::clean_text( $message );
		$location = self::clean_text( $location );
		$basis    = '' !== $key ? 'key:' . $key : preg_replace( '/\d+/', '#', $message );
		return array(
			'id'       => substr( md5( $type . '|' . $location . '|' . $basis ), 0, 12 ),
			'severity' => $severity,
			'type'     => $type,
			'message'  => $message,
			'advice'   => self::clean_text( $advice ),
			'location' => $location,
			'sha1'     => (string) $sha1,
		);
	}

	private function add( $severity, $type, $message, $advice = '', $location = '', $key = '', $sha1 = '' ) {
		$f = $this->make( $severity, $type, $message, $advice, $location, $key, $sha1 );
		foreach ( $this->s['findings'] as $i => $old ) {
			if ( $old['id'] === $f['id'] ) {
				if ( self::sev_rank( $f['severity'] ) > self::sev_rank( $old['severity'] ) ) {
					$this->s['findings'][ $i ] = $f;
				}
				return; // No duplicates, even if a slice is retried.
			}
		}
		if ( count( $this->s['findings'] ) >= self::MAX_FINDINGS ) {
			$this->s['overflow']++;
			return;
		}
		$this->s['findings'][] = $f;
	}
}
