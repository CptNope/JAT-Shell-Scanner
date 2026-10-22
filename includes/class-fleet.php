<?php
/**
 * Fleet: one dashboard for all your sites, self-hosted.
 *
 * Pick one of your WordPress sites as the hub. Every other site ("member")
 * sends a short summary to it after each scan: verdict, PHP and WordPress
 * versions, counts, and the serious findings. Nothing goes anywhere else.
 *
 * Reports are signed with a shared fleet key (HMAC-SHA256) and stamped with
 * the time, so the hub only accepts reports from your own sites and ignores
 * replays.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Fleet {

	const OPTION      = 'wp2ss_fleet';        // Settings: mode, hub url, key.
	const SITES       = 'wp2ss_fleet_sites';  // Hub: reports received, by site.
	const STATUS      = 'wp2ss_fleet_status'; // Member: result of the last send.
	const MAX_SITES   = 1000;
	const MAX_SKEW    = 600;                  // Seconds a report's timestamp may be off.
	const ROUTE_NS    = 'wp2ss/v1';
	const ROUTE       = '/fleet/report';

	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
		add_action( 'wp2ss_scan_complete', array( __CLASS__, 'after_scan' ), 20, 1 );
	}

	/* ------------------------------------------------------------------ */
	/* Settings                                                            */
	/* ------------------------------------------------------------------ */

	public static function settings() {
		$s = get_site_option( self::OPTION, array() );
		return wp_parse_args(
			is_array( $s ) ? $s : array(),
			array(
				'mode' => 'off',   // off | hub | member
				'hub'  => '',      // member: hub site URL
				'key'  => '',      // shared fleet key
			)
		);
	}

	public static function save( $mode, $hub = '', $key = '' ) {
		$s = self::settings();
		if ( ! in_array( $mode, array( 'off', 'hub', 'member' ), true ) ) {
			return new WP_Error( 'wp2ss_mode', __( 'Unknown fleet mode.', 'wp2shell-scanner' ) );
		}
		$s['mode'] = $mode;
		if ( 'hub' === $mode && strlen( $s['key'] ) < 32 ) {
			$s['key'] = self::new_key();
		}
		if ( 'member' === $mode ) {
			$hub = esc_url_raw( trim( (string) $hub ) );
			$key = preg_replace( '/[^A-Za-z0-9]/', '', (string) $key );
			// Plain URL check: wp_http_validate_url() would refuse hubs on a private network or a non-standard port.
			if ( ! $hub || ! filter_var( $hub, FILTER_VALIDATE_URL ) || ! preg_match( '#^https?://#i', $hub ) ) {
				return new WP_Error( 'wp2ss_hub', __( 'Enter the hub site’s address, e.g. https://hub.example.com', 'wp2shell-scanner' ) );
			}
			if ( strlen( $key ) < 32 ) {
				return new WP_Error( 'wp2ss_key', __( 'Paste the fleet key shown on the hub site (it’s 48 characters long).', 'wp2shell-scanner' ) );
			}
			$s['hub'] = untrailingslashit( $hub );
			$s['key'] = $key;
		}
		update_site_option( self::OPTION, $s );
		return $s;
	}

	public static function new_key() {
		return wp_generate_password( 48, false );
	}

	public static function rotate_key() {
		$s        = self::settings();
		$s['key'] = self::new_key();
		update_site_option( self::OPTION, $s );
		return $s['key'];
	}

	/** The hub's address for reports. */
	public static function endpoint( $hub ) {
		return untrailingslashit( $hub ) . '/?rest_route=' . rawurlencode( '/' . self::ROUTE_NS . self::ROUTE );
	}

	/* ------------------------------------------------------------------ */
	/* Member: send a summary after each scan                              */
	/* ------------------------------------------------------------------ */

	/** What a member shares: no file contents, no user emails. */
	public static function summary( $report ) {
		$counts  = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0 );
		$serious = array();
		$ignored = WP2SS_Scanner::ignored();
		foreach ( $report['findings'] as $f ) {
			if ( WP2SS_Scanner::is_ignored( $f, $ignored ) ) {
				continue;
			}
			$weakness = in_array( $f['type'], WP2SS_Scanner::VULN_TYPES, true );
			// Counts are signs of a break-in only; an outdated PHP or WordPress shows in the result label.
			if ( ! $weakness && isset( $counts[ $f['severity'] ] ) ) {
				$counts[ $f['severity'] ]++;
			}
			if ( WP2SS_Scanner::sev_rank( $f['severity'] ) >= 4 && count( $serious ) < 25 ) {
				$serious[] = array(
					'severity' => $f['severity'],
					'type'     => $f['type'],
					'message'  => preg_replace( '/\s*\([^()]*@[^()]*\)/', '', $f['message'] ), // Drop e-mail addresses.
				);
			}
		}
		return array(
			'site'     => $report['site'],
			'name'     => wp_specialchars_decode( get_site_option( 'site_name', get_bloginfo( 'name' ) ), ENT_QUOTES ),
			'admin'    => WP2SS_Admin::url(),
			'verdict'  => WP2SS_Scanner::verdict( $report['findings'], $ignored ),
			'label'    => WP2SS_Admin::verdict_label( WP2SS_Scanner::verdict( $report['findings'], $ignored ), $report['findings'] ),
			'wp'       => $report['wp'],
			'php'      => isset( $report['php']['version'] ) ? $report['php']['version'] : '',
			'sapi'     => isset( $report['php']['sapi'] ) ? $report['php']['sapi'] : '',
			'plugin'   => WP2SS_VERSION,
			'scanned'  => $report['scanned'],
			'source'   => $report['source'],
			'counts'   => $counts,
			'serious'  => $serious,
		);
	}

	public static function after_scan( $report ) {
		$s = self::settings();
		if ( 'hub' === $s['mode'] ) {
			self::store( self::summary( $report ) ); // The hub lists itself too.
		} elseif ( 'member' === $s['mode'] ) {
			self::send( $report );
		}
	}

	/** @return true|WP_Error */
	public static function send( $report = null ) {
		$s      = self::settings();
		$report = $report ? $report : WP2SS_Scanner::last_report();
		if ( 'member' !== $s['mode'] || ! $s['hub'] || ! $s['key'] ) {
			return new WP_Error( 'wp2ss_not_member', __( 'This site isn’t set up to report to a hub.', 'wp2shell-scanner' ) );
		}
		if ( ! $report ) {
			return new WP_Error( 'wp2ss_no_report', __( 'Run a scan first.', 'wp2shell-scanner' ) );
		}
		$body = wp_json_encode( self::summary( $report ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR );
		$ts   = (string) time();
		$res  = wp_remote_post(
			self::endpoint( $s['hub'] ),
			array(
				'timeout' => 10,
				'headers' => array(
					'Content-Type'       => 'application/json',
					'X-WP2SS-Time'       => $ts,
					'X-WP2SS-Signature'  => hash_hmac( 'sha256', $ts . '.' . $body, $s['key'] ),
				),
				'body'    => $body,
			)
		);
		$code   = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
		$ok     = 200 === $code;
		$detail = is_wp_error( $res ) ? $res->get_error_message() : wp_remote_retrieve_body( $res );
		update_site_option(
			self::STATUS,
			array(
				'ok'     => $ok,
				'at'     => time(),
				'code'   => $code,
				'detail' => substr( wp_strip_all_tags( (string) $detail ), 0, 300 ),
			)
		);
		if ( ! $ok ) {
			return new WP_Error( 'wp2ss_send_failed', sprintf( /* translators: 1: HTTP code, 2: detail */ __( 'The hub didn’t accept the report (HTTP %1$s): %2$s', 'wp2shell-scanner' ), $code ? $code : '—', substr( wp_strip_all_tags( (string) $detail ), 0, 200 ) ) );
		}
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Hub: receive and store                                              */
	/* ------------------------------------------------------------------ */

	public static function routes() {
		register_rest_route(
			self::ROUTE_NS,
			self::ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'receive' ),
				// Authentication is the HMAC signature checked in receive(); the route is useless without the fleet key.
				'permission_callback' => '__return_true',
			)
		);
	}

	public static function receive( WP_REST_Request $req ) {
		$s = self::settings();
		if ( 'hub' !== $s['mode'] || strlen( $s['key'] ) < 32 ) {
			return new WP_Error( 'wp2ss_not_hub', 'This site is not a fleet hub.', array( 'status' => 404 ) );
		}
		$ts   = (string) $req->get_header( 'x_wp2ss_time' );
		$sig  = (string) $req->get_header( 'x_wp2ss_signature' );
		$body = (string) $req->get_body();
		if ( ! ctype_digit( $ts ) || abs( time() - (int) $ts ) > self::MAX_SKEW ) {
			return new WP_Error( 'wp2ss_time', 'Report timestamp missing or too far off — check the sending server’s clock.', array( 'status' => 401 ) );
		}
		if ( ! hash_equals( hash_hmac( 'sha256', $ts . '.' . $body, $s['key'] ), $sig ) ) {
			return new WP_Error( 'wp2ss_sig', 'Bad signature — the fleet key on the sending site doesn’t match this hub.', array( 'status' => 401 ) );
		}
		if ( strlen( $body ) > 65536 ) {
			return new WP_Error( 'wp2ss_size', 'Report too large.', array( 'status' => 413 ) );
		}
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) || empty( $data['site'] ) ) {
			return new WP_Error( 'wp2ss_body', 'Malformed report.', array( 'status' => 400 ) );
		}
		$stored = self::store( $data, $ts );
		if ( is_wp_error( $stored ) ) {
			return $stored;
		}
		return rest_ensure_response( array( 'ok' => true ) );
	}

	/** Keep only known fields, as plain text. */
	private static function clean( $d ) {
		$t   = function ( $v, $len = 200 ) {
			return substr( sanitize_text_field( (string) $v ), 0, $len );
		};
		$out = array(
			'site'    => esc_url_raw( (string) $d['site'] ),
			'name'    => $t( isset( $d['name'] ) ? $d['name'] : '' ),
			'admin'   => esc_url_raw( isset( $d['admin'] ) ? (string) $d['admin'] : '' ),
			'verdict' => in_array( isset( $d['verdict'] ) ? $d['verdict'] : '', array( 'CLEAN', 'REVIEW', 'VULNERABLE', 'SUSPICIOUS', 'COMPROMISED' ), true ) ? $d['verdict'] : 'REVIEW',
			'label'   => $t( isset( $d['label'] ) ? $d['label'] : '' ),
			'wp'      => $t( isset( $d['wp'] ) ? $d['wp'] : '', 20 ),
			'php'     => $t( isset( $d['php'] ) ? $d['php'] : '', 40 ),
			'sapi'    => $t( isset( $d['sapi'] ) ? $d['sapi'] : '', 20 ),
			'plugin'  => $t( isset( $d['plugin'] ) ? $d['plugin'] : '', 20 ),
			'scanned' => $t( isset( $d['scanned'] ) ? $d['scanned'] : '', 40 ),
			'source'  => $t( isset( $d['source'] ) ? $d['source'] : '', 10 ),
			'counts'  => array(),
			'serious' => array(),
		);
		foreach ( array( 'critical', 'high', 'medium', 'low' ) as $k ) {
			$out['counts'][ $k ] = isset( $d['counts'][ $k ] ) ? max( 0, (int) $d['counts'][ $k ] ) : 0;
		}
		foreach ( array_slice( isset( $d['serious'] ) && is_array( $d['serious'] ) ? $d['serious'] : array(), 0, 25 ) as $f ) {
			$out['serious'][] = array(
				'severity' => in_array( isset( $f['severity'] ) ? $f['severity'] : '', array( 'critical', 'high' ), true ) ? $f['severity'] : 'high',
				'type'     => $t( isset( $f['type'] ) ? $f['type'] : '', 20 ),
				'message'  => $t( isset( $f['message'] ) ? $f['message'] : '', 400 ),
			);
		}
		return $out;
	}

	private static function store( $data, $ts = null ) {
		$d = self::clean( $data );
		if ( ! $d['site'] ) {
			return new WP_Error( 'wp2ss_body', 'Malformed report.', array( 'status' => 400 ) );
		}
		$key   = md5( strtolower( untrailingslashit( preg_replace( '#^https?://#i', '', $d['site'] ) ) ) );
		$sites = get_site_option( self::SITES, array() );
		$sites = is_array( $sites ) ? $sites : array();
		if ( $ts && isset( $sites[ $key ]['ts'] ) && (int) $ts < (int) $sites[ $key ]['ts'] ) {
			return new WP_Error( 'wp2ss_replay', 'Older than the report already stored.', array( 'status' => 409 ) );
		}
		if ( ! isset( $sites[ $key ] ) && count( $sites ) >= self::MAX_SITES ) {
			return new WP_Error( 'wp2ss_full', 'This hub already tracks the maximum number of sites.', array( 'status' => 507 ) );
		}
		$d['received'] = time();
		$d['ts']       = $ts ? (int) $ts : time();
		$sites[ $key ] = $d;
		update_site_option( self::SITES, $sites );
		return true;
	}

	public static function sites() {
		$sites = get_site_option( self::SITES, array() );
		$sites = is_array( $sites ) ? $sites : array();
		$rank  = array( 'COMPROMISED' => 0, 'SUSPICIOUS' => 1, 'VULNERABLE' => 2, 'REVIEW' => 3, 'CLEAN' => 4 );
		uasort(
			$sites,
			function ( $a, $b ) use ( $rank ) {
				$c = $rank[ $a['verdict'] ] - $rank[ $b['verdict'] ];
				return $c ? $c : strcmp( $a['site'], $b['site'] );
			}
		);
		return $sites;
	}

	public static function forget( $key ) {
		$sites = get_site_option( self::SITES, array() );
		if ( is_array( $sites ) && isset( $sites[ $key ] ) ) {
			unset( $sites[ $key ] );
			update_site_option( self::SITES, $sites );
		}
	}

	/** A report is stale if no scan arrived for twice the weekly schedule. */
	public static function is_stale( $site ) {
		return time() - (int) $site['received'] > 15 * DAY_IN_SECONDS;
	}
}
