<?php
/**
 * The web server's PHP environment.
 *
 * PHP2Shell is a bug in PHP itself, so what matters is the PHP that serves
 * web pages. WP-CLI often runs a different PHP binary (with a different
 * version and php.ini), so whenever the plugin runs inside a web request it
 * records a snapshot, and scans started from the command line use that.
 *
 * A short history of PHP versions is kept too, so the scanner can tell when a
 * site ran a vulnerable PHP during the attack window even if it's patched now.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Env {

	const OPTION = 'wp2ss_env';

	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'record' ) );
		add_action( WP2SS_Cron::HOOK, array( __CLASS__, 'record' ), 1 );
		add_action( WP2SS_Cron::STEP_HOOK, array( __CLASS__, 'record' ), 1 );
	}

	/** Live values of the PHP running this request. */
	public static function live() {
		$ini = function_exists( 'ini_get_all' ) ? @ini_get_all( null, true ) : array(); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$g   = function ( $k ) use ( $ini ) {
			if ( isset( $ini[ $k ]['global_value'] ) ) {
				return (string) $ini[ $k ]['global_value']; // The server's php.ini value, before WordPress changes it.
			}
			$v = ini_get( $k );
			return false === $v ? null : (string) $v;
		};

		return array(
			'version'         => PHP_VERSION,
			'extra'           => defined( 'PHP_EXTRA_VERSION' ) ? PHP_EXTRA_VERSION : '',
			'branch'          => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
			'sapi'            => PHP_SAPI,
			'os'              => self::os_id(),
			'server'          => isset( $_SERVER['SERVER_SOFTWARE'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ), 0, 80 ) : '',
			'upload_progress' => $g( 'session.upload_progress.enabled' ),
			'memory_limit'    => $g( 'memory_limit' ),
			'fatal_bt'        => $g( 'fatal_error_backtraces' ),
			'error_log'       => $g( 'error_log' ),
			'time'            => time(),
		);
	}

	/** Linux distribution ID from /etc/os-release, if PHP may read it. */
	private static function os_id() {
		if ( 'Linux' !== PHP_OS ) {
			return PHP_OS;
		}
		$f = '/etc/os-release';
		$s = @is_readable( $f ) ? @file_get_contents( $f, false, null, 0, 4096 ) : false; // phpcs:ignore
		if ( $s && preg_match( '/^ID="?([a-z0-9._-]+)"?/m', $s, $m ) ) {
			return $m[1];
		}
		return 'linux';
	}

	/** Save a snapshot when running under the web server (at most hourly unless something changed). */
	public static function record() {
		if ( 'cli' === PHP_SAPI || 'phpdbg' === PHP_SAPI ) {
			return;
		}
		$old  = get_site_option( self::OPTION );
		$live = self::live();
		if ( is_array( $old ) && isset( $old['version'] ) && $old['version'] === $live['version']
			&& $old['sapi'] === $live['sapi'] && $old['upload_progress'] === $live['upload_progress']
			&& $old['memory_limit'] === $live['memory_limit'] && time() - (int) $old['time'] < HOUR_IN_SECONDS ) {
			return;
		}

		$history = ( is_array( $old ) && ! empty( $old['history'] ) ) ? $old['history'] : array();
		$last    = $history ? $history[ count( $history ) - 1 ] : null;
		if ( $last && $last['v'] === $live['version'] && $last['sapi'] === $live['sapi'] ) {
			$history[ count( $history ) - 1 ]['last'] = time();
		} else {
			$history[] = array( 'v' => $live['version'], 'extra' => $live['extra'], 'sapi' => $live['sapi'], 'first' => time(), 'last' => time() );
			$history   = array_slice( $history, -10 );
		}
		$live['history'] = $history;
		update_site_option( self::OPTION, $live );
	}

	/**
	 * The environment to judge: the live one in a web request, otherwise the
	 * last web snapshot (falling back to the CLI's own PHP, clearly marked).
	 */
	public static function get() {
		if ( 'cli' !== PHP_SAPI && 'phpdbg' !== PHP_SAPI ) {
			self::record();
			$e           = get_site_option( self::OPTION );
			$e           = is_array( $e ) ? $e : self::live();
			$e['source'] = 'web';
			return $e;
		}
		$e = get_site_option( self::OPTION );
		if ( is_array( $e ) && ! empty( $e['version'] ) ) {
			$e['source'] = 'web-snapshot';
			return $e;
		}
		$e            = self::live();
		$e['history'] = array();
		$e['source']  = 'cli';
		return $e;
	}

	/** True if PHP is a Linux-distribution build that may carry backported fixes without a version bump. */
	public static function maybe_backported( $e ) {
		if ( '' !== (string) $e['extra'] || preg_match( '/ubuntu|deb|\.el\d|cloudlinux|remi|alt|ea-php|lsphp/i', $e['version'] ) ) {
			return true;
		}
		return in_array( strtolower( (string) $e['os'] ), array( 'ubuntu', 'debian', 'rhel', 'almalinux', 'rocky', 'centos', 'cloudlinux', 'ol', 'amzn', 'sles', 'opensuse-leap', 'fedora' ), true );
	}

	/**
	 * Is this PHP version affected by PHP2Shell?
	 *
	 * @return string 'fixed' | 'newer' | 'vulnerable' | 'backport-only' | 'no-fix'
	 */
	public static function php2shell_status( $version, $sig ) {
		if ( ! preg_match( '/^(\d+)\.(\d+)\.(\d+)/', (string) $version, $m ) ) {
			return 'vulnerable';
		}
		$branch = $m[1] . '.' . $m[2];
		$num    = $m[1] . '.' . $m[2] . '.' . $m[3];
		if ( isset( $sig['php_fixed'][ $branch ] ) ) {
			return version_compare( $num, $sig['php_fixed'][ $branch ], '>=' ) ? 'fixed' : 'vulnerable';
		}
		$newest = array_keys( $sig['php_fixed'] );
		if ( version_compare( $branch, end( $newest ), '>' ) ) {
			return 'newer';
		}
		if ( in_array( $branch, $sig['php_backport_only'], true ) ) {
			return 'backport-only';
		}
		return 'no-fix';
	}
}
