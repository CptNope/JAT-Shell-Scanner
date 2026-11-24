<?php
/**
 * A plain-language summary of a scan that a site owner can forward to their
 * host or developer as it is: the result in one sentence, each Critical and
 * High finding in plain words, and the facts a host would otherwise ask for.
 *
 * It never includes file contents, passwords or personal data: account names,
 * email addresses and IP addresses are left out. Only paths and short
 * descriptions go in.
 *
 * @package JAT_Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Summary {

	/** The CVEs this scanner checks for, so the host doesn't have to ask. */
	const CVES = 'PHP2Shell (CVE-2026-109618, CVE-2026-109619, CVE-2026-115560) and wp2shell (CVE-2026-63030, CVE-2026-60137)';

	/**
	 * The summary as plain text.
	 *
	 * @param array      $report  A scan report (WP2SS_Scanner::last_report()).
	 * @param array|null $ignored Ignore list; defaults to the site's.
	 * @return string
	 */
	public static function text( $report, $ignored = null ) {
		if ( ! is_array( $report ) || empty( $report['scanned'] ) ) {
			return '';
		}
		$ignored  = null === $ignored ? WP2SS_Scanner::ignored() : $ignored;
		$findings = isset( $report['findings'] ) ? (array) $report['findings'] : array();
		$verdict  = WP2SS_Scanner::verdict( $findings, $ignored );
		list( $php, $wp, $in ) = WP2SS_Admin::doors( $findings, $ignored );

		$out   = array();
		$out[] = sprintf(
			/* translators: %s: site address */
			__( 'Security scan summary for %s', 'jat-shell-scanner' ),
			self::plain( $report['site'] )
		);
		$out[] = '';
		$out[] = __( 'Result:', 'jat-shell-scanner' ) . ' ' . WP2SS_Admin::sentence( $verdict, $php, $wp, $in );
		if ( WP2SS_Scanner::protections_only( $findings, $ignored ) ) {
			$out[] = WP2SS_Admin::protections_line();
		}

		// Critical and High, worst first; the rest only as a count.
		$serious = array();
		$medium  = 0;
		foreach ( $findings as $f ) {
			if ( WP2SS_Scanner::is_ignored( $f, $ignored ) ) {
				continue;
			}
			$rank = WP2SS_Scanner::sev_rank( $f['severity'] );
			if ( $rank >= 4 ) {
				$serious[] = $f;
			} elseif ( 3 === $rank ) {
				$medium++;
			}
		}
		usort(
			$serious,
			function ( $a, $b ) {
				return WP2SS_Scanner::sev_rank( $b['severity'] ) - WP2SS_Scanner::sev_rank( $a['severity'] );
			}
		);

		$out[] = '';
		if ( $serious ) {
			/* translators: %d: number of findings */
			$out[] = sprintf( _n( 'What needs attention (%d item):', 'What needs attention (%d items):', count( $serious ), 'jat-shell-scanner' ), count( $serious ) );
			$n = 0;
			foreach ( $serious as $f ) {
				$n++;
				$out[] = '';
				$out[] = sprintf( '%d. %s: %s', $n, strtoupper( WP2SS_Admin::sev_label( $f['severity'] ) ), self::redact( $f ) );
				$where = self::where( $f );
				if ( '' !== $where && false === strpos( self::redact( $f ), strtok( $where, ' ' ) ) ) {
					$out[] = '   ' . __( 'Where:', 'jat-shell-scanner' ) . ' ' . $where;
				}
				$todo = self::todo( $f, $report );
				if ( '' !== $todo ) {
					$out[] = '   ' . __( 'What to do:', 'jat-shell-scanner' ) . ' ' . $todo;
				}
				$fix = class_exists( 'WP2SS_Fixes' ) ? WP2SS_Fixes::record_for_finding( $f ) : null;
				if ( $fix ) {
					$out[] = '   ' . ( 'demote' === $fix['action']
						? __( 'Status: the site owner has already removed this account’s admin rights.', 'jat-shell-scanner' )
						: __( 'Status: the site owner has already moved this to quarantine (it can’t run there).', 'jat-shell-scanner' ) );
				}
			}
		} else {
			$out[] = __( 'Nothing critical or high was found.', 'jat-shell-scanner' );
		}
		if ( $medium ) {
			$out[] = '';
			/* translators: %d: number of findings */
			$out[] = sprintf( _n( 'There is also %d medium-level item, which the site owner is reviewing.', 'There are also %d medium-level items, which the site owner is reviewing.', $medium, 'jat-shell-scanner' ), $medium );
		}

		$env = WP2SS_Env::get();
		$ver = isset( $report['php']['version'] ) ? $report['php']['version'] : $env['version'];
		if ( ! empty( $env['pkg'] ) && $ver === $env['version'] ) {
			/* translators: %s: operating-system package version */
			$ver .= ' ' . sprintf( __( '(package %s)', 'jat-shell-scanner' ), $env['pkg'] );
		}
		if ( ! empty( $report['php']['sapi'] ) ) {
			$ver .= ', ' . WP2SS_Admin::sapi_label( $report['php']['sapi'] );
		}

		$out[] = '';
		$out[] = __( 'Details', 'jat-shell-scanner' );
		$out[] = __( 'Site:', 'jat-shell-scanner' ) . ' ' . self::plain( $report['site'] );
		$out[] = __( 'WordPress:', 'jat-shell-scanner' ) . ' ' . self::plain( $report['wp'] );
		$out[] = __( 'PHP:', 'jat-shell-scanner' ) . ' ' . self::plain( $ver );
		$out[] = __( 'Scanned:', 'jat-shell-scanner' ) . ' ' . gmdate( 'Y-m-d H:i', strtotime( $report['scanned'] ) ) . ' UTC';
		$out[] = __( 'Checked for:', 'jat-shell-scanner' ) . ' ' . self::CVES;
		$out[] = sprintf(
			/* translators: 1: plugin version, 2: plugin page address */
			__( 'Scanner: JAT Shell Scanner %1$s (%2$s)', 'jat-shell-scanner' ),
			WP2SS_VERSION,
			'https://wordpress.org/plugins/jat-shell-scanner/'
		);
		$out[] = '';
		$out[] = __( 'This summary leaves out file contents, passwords and personal data (account names, email and IP addresses). The full details are in the scanner on the site.', 'jat-shell-scanner' );

		return implode( "\n", $out ) . "\n";
	}

	/** One line of text: no tags, no control characters. */
	private static function plain( $s ) {
		return trim( preg_replace( '/[\x00-\x1F\x7F]+/u', ' ', wp_strip_all_tags( (string) $s ) ) );
	}

	/** The finding in plain words, without account names, email addresses or IP addresses. */
	public static function redact( $f ) {
		$m = self::plain( $f['message'] );
		$m = preg_replace( '/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', '[email address]', $m );
		// Only real IP addresses (a time like 01:26:40 is not one).
		$m = preg_replace_callback(
			'/(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})(?![\w:])/i',
			function ( $x ) {
				return filter_var( $x[0], FILTER_VALIDATE_IP ) ? '[IP address]' : $x[0];
			},
			$m
		);
		if ( 'user' === $f['type'] ) {
			// Account names appear in quotes in these messages.
			$m = preg_replace( '/[“"][^”"]{1,120}[”"]/u', '[account name]', $m );
		}
		return mb_substr( $m, 0, 400 );
	}

	/** Where it is, as the host sees it: a path from the site folder, never an account id. */
	private static function where( $f ) {
		$loc = self::plain( $f['location'] );
		if ( '' === $loc || 'user' === $f['type'] || preg_match( '/^user:/', $loc ) ) {
			return '';
		}
		$root = wp_normalize_path( untrailingslashit( WP2SS_Paths::core() ) );
		$norm = wp_normalize_path( $loc );
		if ( 0 === strpos( $norm, $root . '/' ) ) {
			return substr( $norm, strlen( $root ) + 1 ) . ' ' . __( '(in the site folder)', 'jat-shell-scanner' );
		}
		return $loc;
	}

	/** What the host should do: the finding's advice, minus the parts only make sense on the scanner page. */
	private static function todo( $f, $report ) {
		if ( 'php' === $f['type'] ) {
			$sig    = WP2SS_Scanner::signatures();
			$branch = isset( $report['php']['version'] ) ? implode( '.', array_slice( explode( '.', $report['php']['version'] ), 0, 2 ) ) : '';
			$fixed  = isset( $sig['php_fixed'][ $branch ] ) ? $sig['php_fixed'][ $branch ] : '8.2.35';
			/* translators: %s: fixed PHP version */
			return sprintf( __( 'Update PHP to %s or later (or install your patched package), then fully restart PHP. Temporary php.ini protections only partly help.', 'jat-shell-scanner' ), $fixed );
		}
		$keep = array();
		foreach ( preg_split( '/(?<=[.!?])\s+/u', self::plain( $f['advice'] ) ) as $s ) {
			if ( '' !== $s && ! preg_match( '/scanner page|ready-to-send|click|Ignore|Quarantine tab|this page|below|button/i', $s ) ) {
				$keep[] = $s;
			}
		}
		$t = self::redact( array( 'message' => implode( ' ', $keep ), 'type' => $f['type'] ) );
		return $t;
	}
}
