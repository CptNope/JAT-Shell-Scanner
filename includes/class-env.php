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
			'post_max_size'   => $g( 'post_max_size' ),
			'max_nesting'     => $g( 'max_input_nesting_level' ),
			'pkg'             => self::package_version( PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION ),
			'build'           => self::build_date(),
			'time'            => time(),
		);
	}

	/**
	 * Version of the Debian/Ubuntu PHP package, from the package database
	 * (world-readable on most servers). Distributions often fix PHP without
	 * changing PHP's own version number; the package version says exactly.
	 */
	private static function package_version( $branch ) {
		$f = '/var/lib/dpkg/status';
		if ( 'Linux' !== PHP_OS || ! @is_readable( $f ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return '';
		}
		$fh = @fopen( $f, 'rb' ); // phpcs:ignore
		if ( ! $fh ) {
			return '';
		}
		$want = array( "php$branch-common", "php$branch-fpm", "libapache2-mod-php$branch", "php$branch-cli", "php$branch-cgi" );
		$pkg  = '';
		$out  = '';
		while ( false !== ( $line = fgets( $fh, 4096 ) ) ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition
			if ( 0 === strpos( $line, 'Package: ' ) ) {
				$pkg = trim( substr( $line, 9 ) );
			} elseif ( $pkg && 0 === strpos( $line, 'Version: ' ) && in_array( $pkg, $want, true ) ) {
				$out = trim( substr( $line, 9 ) );
				if ( "php$branch-common" === $pkg ) {
					break; // The shared package is the best single answer.
				}
			}
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- Read-only streaming of a file being scanned; WP_Filesystem has no partial reads.
		return substr( $out, 0, 60 );
	}

	/** When this PHP binary was built (from phpinfo), as a timestamp; 0 if unknown. */
	private static function build_date() {
		if ( ! function_exists( 'phpinfo' ) || false !== stripos( (string) ini_get( 'disable_functions' ), 'phpinfo' ) ) {
			return 0;
		}
		ob_start();
		phpinfo( INFO_GENERAL ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.prevent_path_disclosure_phpinfo -- Output is captured, never shown; only PHP's build date is read from it.
		$s = (string) ob_get_clean();
		if ( preg_match( '/Build Date\s*(?:=>|<\/td><td[^>]*>)\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}(?:\s+\d{2}:\d{2}:\d{2})?)/', $s, $m ) ) {
			$t = strtotime( preg_replace( '/\s+/', ' ', $m[1] ) . ' UTC' );
			return $t ? (int) $t : 0;
		}
		return 0;
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
			&& isset( $old['pkg'] ) && $old['pkg'] === $live['pkg']
			&& $old['memory_limit'] === $live['memory_limit'] && time() - (int) $old['time'] < HOUR_IN_SECONDS ) {
			return;
		}

		$history = ( is_array( $old ) && ! empty( $old['history'] ) ) ? $old['history'] : array();
		$last    = $history ? $history[ count( $history ) - 1 ] : null;
		if ( $last && $last['v'] === $live['version'] && $last['sapi'] === $live['sapi'] && ( isset( $last['pkg'] ) ? $last['pkg'] : '' ) === $live['pkg'] ) {
			$history[ count( $history ) - 1 ]['last'] = time();
		} else {
			$history[] = array( 'v' => $live['version'], 'extra' => $live['extra'], 'pkg' => $live['pkg'], 'build' => $live['build'], 'sapi' => $live['sapi'], 'first' => time(), 'last' => time() );
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
	 * PHP2Shell status for a whole environment: uses the package version and
	 * build date where the bare version number can't tell.
	 *
	 * @return array [ status, how ] — how: 'version' | 'package' | 'build'.
	 */
	public static function php2shell_status_env( $e, $sig ) {
		$status = self::php2shell_status( $e['version'], $sig );
		if ( in_array( $status, array( 'fixed', 'newer' ), true ) ) {
			return array( $status, 'version' );
		}
		$pkg = isset( $e['pkg'] ) ? (string) $e['pkg'] : '';
		foreach ( $sig['php_fixed_pkg'] as $p ) {
			if ( $pkg && 0 === strpos( $pkg, $p[0] ) && preg_match( '/^\d+/', substr( $pkg, strlen( $p[0] ) ), $m ) ) {
				return array( (int) $m[0] >= (int) $p[1] ? 'fixed' : 'pkg-vulnerable', 'package' );
			}
		}
		if ( ! empty( $e['build'] ) && (int) $e['build'] >= (int) $sig['php_fix_date'] && 'no-fix' !== $status ) {
			return array( 'build-after-fix', 'build' );
		}
		return array( $status, 'version' );
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
