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
	const PINS        = 'wp2ss_fleet_pins';   // Hub: each member site's own secret, registered on its first report.
	const MAX_SITES   = 500;
	const MAX_SKEW    = 600;                  // Seconds a report may be old (slow clocks, queues).
	const MAX_AHEAD   = 60;                   // Seconds a report may be "from the future".
	const MAX_BODY    = 32768;
	const ROUTE_NS    = 'wp2ss/v1';
	const ROUTE       = '/fleet/report';
	const POLL_ROUTE  = '/fleet/poll';
	const QUEUE       = 'wp2ss_fleet_queue';  // Hub: alert events waiting to be sent as one digest.
	const ALERT_HOOK  = 'wp2ss_fleet_alerts';
	const DAILY_HOOK  = 'wp2ss_fleet_daily';
	const POLL_HOOK   = 'wp2ss_fleet_poll';
	const DIGEST_WAIT = 120;                  // Seconds to collect events before sending a digest.
	const RANK        = array( 'COMPROMISED' => 0, 'SUSPICIOUS' => 1, 'VULNERABLE' => 2, 'REVIEW' => 3, 'CLEAN' => 4 );

	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
		add_action( 'wp2ss_scan_complete', array( __CLASS__, 'after_scan' ), 20, 1 );
		add_action( self::ALERT_HOOK, array( __CLASS__, 'send_digest' ) );
		add_action( self::DAILY_HOOK, array( __CLASS__, 'check_stale' ) );
		add_action( self::POLL_HOOK, array( __CLASS__, 'poll' ) );
		add_action( 'admin_init', array( __CLASS__, 'ensure_schedule' ) );
	}

	/** Scheduled events live on one site only (the main site on multisite). */
	private static function in_charge() {
		return ! is_multisite() || is_main_site();
	}

	/** Hub: daily overdue check. Member: hourly check-in for scan requests. */
	public static function ensure_schedule() {
		if ( ! self::in_charge() ) {
			return;
		}
		$mode = self::settings()['mode'];
		$want = array(
			self::DAILY_HOOK => 'hub' === $mode ? 'daily' : '',
			self::POLL_HOOK  => 'member' === $mode ? 'hourly' : '',
		);
		foreach ( $want as $hook => $recurrence ) {
			$next = wp_next_scheduled( $hook );
			if ( $recurrence && ! $next ) {
				wp_schedule_event( time() + wp_rand( 60, 900 ), $recurrence, $hook );
			} elseif ( ! $recurrence && $next ) {
				wp_clear_scheduled_hook( $hook );
			}
		}
	}

	public static function unschedule() {
		foreach ( array( self::ALERT_HOOK, self::DAILY_HOOK, self::POLL_HOOK ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Settings                                                            */
	/* ------------------------------------------------------------------ */

	public static function settings() {
		$s = get_site_option( self::OPTION, array() );
		return wp_parse_args(
			is_array( $s ) ? $s : array(),
			array(
				'mode'          => 'off',   // off | hub | member
				'hub'           => '',      // member: hub site URL
				'key'           => '',      // shared fleet key
				'secret'        => '',      // member: this site's own secret, registered with the hub
				'enrolled'      => false,   // member: the hub has registered this site's secret
				'alert_email'   => true,    // hub: email a digest when sites need attention
				'alert_to'      => '',      // hub: address for it ('' = the scanner's alert address)
				'alert_webhook' => '',      // hub: Slack / Discord incoming-webhook URL
				'alert_stale'   => true,    // hub: also alert when a site stops reporting
				'stale_days'    => 15,      // hub: days without a report before a site is overdue
			)
		);
	}

	public static function save( $mode, $hub = '', $key = '' ) {
		$s = self::settings();
		if ( ! in_array( $mode, array( 'off', 'hub', 'member' ), true ) ) {
			return new WP_Error( 'wp2ss_mode', __( 'Unknown fleet mode.', 'php2shell-scanner' ) );
		}
		$s['mode'] = $mode;
		if ( 'hub' === $mode && strlen( $s['key'] ) < 32 ) {
			$s['key'] = self::new_key();
		}
		if ( 'member' === $mode ) {
			$hub = esc_url_raw( trim( (string) $hub ) );
			$key = preg_replace( '/[^A-Za-z0-9]/', '', (string) $key );
			if ( '' === $key && 'member' === $s['mode'] ) {
				$key = $s['key']; // Field left blank: keep the saved key.
			}
			// Plain URL check: wp_http_validate_url() would refuse hubs on a private network or a non-standard port.
			if ( ! $hub || ! filter_var( $hub, FILTER_VALIDATE_URL ) || ! preg_match( '#^https?://#i', $hub ) ) {
				return new WP_Error( 'wp2ss_hub', __( 'Enter the hub site’s address, e.g. https://hub.example.com', 'php2shell-scanner' ) );
			}
			if ( strlen( $key ) < 32 ) {
				return new WP_Error( 'wp2ss_key', __( 'Paste the fleet key shown on the hub site (it’s 48 characters long).', 'php2shell-scanner' ) );
			}
			if ( untrailingslashit( $hub ) !== $s['hub'] ) {
				$s['enrolled'] = false;
			}
			$s['hub'] = untrailingslashit( $hub );
			$s['key'] = $key;
			if ( strlen( $s['secret'] ) < 32 ) {
				// Kept when re-joining, so the hub still recognises this site.
				$s['secret']   = wp_generate_password( 48, false );
				$s['enrolled'] = false;
			}
		}
		update_site_option( self::OPTION, $s );
		self::ensure_schedule();
		return $s;
	}

	/** Hub alert settings. @return array|WP_Error */
	public static function save_alerts( $email, $to, $webhook, $stale, $stale_days ) {
		$s       = self::settings();
		$to      = trim( (string) $to );
		$webhook = trim( (string) $webhook );
		if ( '' !== $to && ! is_email( $to ) ) {
			return new WP_Error( 'wp2ss_alert_to', __( 'That email address doesn’t look right.', 'php2shell-scanner' ) );
		}
		if ( '' !== $webhook && ( ! filter_var( $webhook, FILTER_VALIDATE_URL ) || 0 !== stripos( $webhook, 'https://' ) ) ) {
			return new WP_Error( 'wp2ss_webhook', __( 'The webhook address must start with https:// — copy it from Slack or Discord.', 'php2shell-scanner' ) );
		}
		$s['alert_email']   = (bool) $email;
		$s['alert_to']      = $to;
		$s['alert_webhook'] = esc_url_raw( $webhook, array( 'https' ) );
		$s['alert_stale']   = (bool) $stale;
		$s['stale_days']    = max( 2, min( 90, (int) $stale_days ) );
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
			if ( WP2SS_Scanner::sev_rank( $f['severity'] ) >= 4 && count( $serious ) < 10 ) {
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
			return new WP_Error( 'wp2ss_not_member', __( 'This site isn’t set up to report to a hub.', 'php2shell-scanner' ) );
		}
		if ( ! $report ) {
			return new WP_Error( 'wp2ss_no_report', __( 'Run a scan first.', 'php2shell-scanner' ) );
		}
		$data = self::summary( $report );
		if ( ! $s['enrolled'] ) {
			$data['enroll'] = $s['secret'];
		}
		$res    = self::signed_post( $s, self::ROUTE, $data );
		$code   = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
		$ok     = 200 === $code;
		$detail = is_wp_error( $res ) ? $res->get_error_message() : self::reply_message( $res );
		if ( $ok ) {
			$reply    = json_decode( (string) wp_remote_retrieve_body( $res ), true );
			$enrolled = ! empty( $reply['enrolled'] );
			if ( $enrolled !== (bool) $s['enrolled'] ) {
				$was           = $s['enrolled'];
				$s['enrolled'] = $enrolled;
				update_site_option( self::OPTION, $s );
				if ( $was && ! $enrolled ) {
					return self::send( $report ); // The hub forgot this site: register again right away.
				}
			}
		}
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
			return new WP_Error( 'wp2ss_send_failed', sprintf( /* translators: 1: HTTP code, 2: detail */ __( 'The hub didn’t accept the report (HTTP %1$s): %2$s', 'php2shell-scanner' ), $code ? $code : '—', substr( wp_strip_all_tags( (string) $detail ), 0, 200 ) ) );
		}
		return true;
	}

	private static function signed_post( $s, $route, $data ) {
		$body = wp_json_encode( $data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR );
		$ts   = (string) time();
		$args = array(
			'timeout'     => 10,
			'redirection' => 0, // A hub never redirects; following one could send the report somewhere else.
			'headers'     => array(
				'Content-Type'           => 'application/json',
				'X-WP2SS-Time'           => $ts,
				'X-WP2SS-Signature'      => hash_hmac( 'sha256', $ts . '.' . $body, $s['key'] ),
				'X-WP2SS-Site-Signature' => hash_hmac( 'sha256', $ts . '.' . $body, $s['secret'] ),
			),
			'body'        => $body,
		);
		$url = untrailingslashit( $s['hub'] ) . '/?rest_route=' . rawurlencode( '/' . self::ROUTE_NS . $route );
		/**
		 * Allow a hub on a private network address (e.g. 10.x, 192.168.x, localhost).
		 * Off by default, so the hub address can't be used to probe the local network.
		 *
		 * @param bool $allow Default: the WP2SS_FLEET_PRIVATE_HUB constant.
		 */
		$private = apply_filters( 'wp2ss_fleet_private_hub', defined( 'WP2SS_FLEET_PRIVATE_HUB' ) && WP2SS_FLEET_PRIVATE_HUB );
		return $private ? wp_remote_post( $url, $args ) : wp_safe_remote_post( $url, $args );
	}

	/** Only the hub's own error message, never arbitrary page content. */
	private static function reply_message( $res ) {
		$j = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		return is_array( $j ) && isset( $j['message'] ) && is_string( $j['message'] ) ? substr( wp_strip_all_tags( $j['message'] ), 0, 200 ) : '';
	}

	/**
	 * Member: hourly check-in. If someone on the hub asked for a new scan,
	 * start one (it reports back when it finishes).
	 *
	 * @return bool|WP_Error True if a scan was started.
	 */
	public static function poll() {
		$s = self::settings();
		if ( 'member' !== $s['mode'] || ! $s['hub'] || ! $s['key'] ) {
			return false;
		}
		$res = self::signed_post( $s, self::POLL_ROUTE, array( 'site' => self::own_url() ) );
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return is_wp_error( $res ) ? $res : new WP_Error( 'wp2ss_poll', 'HTTP ' . wp_remote_retrieve_response_code( $res ) );
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		if ( empty( $data['rescan'] ) || WP2SS_Scanner::current() ) {
			return false;
		}
		WP2SS_Scanner::start( WP2SS_Settings::scan_args(), 'cron' );
		if ( ! wp_next_scheduled( WP2SS_Cron::STEP_HOOK ) ) {
			wp_schedule_single_event( time() + 5, WP2SS_Cron::STEP_HOOK );
		}
		return true;
	}

	/** The address this site reports under (same as a scan report's "site"). */
	private static function own_url() {
		return untrailingslashit( network_home_url() );
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
		register_rest_route(
			self::ROUTE_NS,
			self::POLL_ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'receive_poll' ),
				'permission_callback' => '__return_true', // Same HMAC check as reports.
			)
		);
	}

	/** Check a signed request. @return array|WP_Error [ data, timestamp ] */
	/**
	 * Check a signed request: the fleet key proves it's one of your sites,
	 * and the site's own registered secret proves which one.
	 *
	 * @return array|WP_Error [ data, timestamp, legacy ]
	 */
	private static function verify( WP_REST_Request $req, $allow_enroll = true ) {
		$s = self::settings();
		if ( 'hub' !== $s['mode'] || strlen( $s['key'] ) < 32 ) {
			return new WP_Error( 'wp2ss_not_hub', 'This site is not a fleet hub.', array( 'status' => 404 ) );
		}
		$body = (string) $req->get_body();
		if ( strlen( $body ) > self::MAX_BODY ) {
			return new WP_Error( 'wp2ss_size', 'Report too large.', array( 'status' => 413 ) );
		}
		$ts  = (string) $req->get_header( 'x_wp2ss_time' );
		$sig = (string) $req->get_header( 'x_wp2ss_signature' );
		if ( ! ctype_digit( $ts ) || time() - (int) $ts > self::MAX_SKEW || (int) $ts - time() > self::MAX_AHEAD ) {
			return new WP_Error( 'wp2ss_time', 'Report timestamp missing or too far off — check the sending server’s clock.', array( 'status' => 401 ) );
		}
		if ( ! hash_equals( hash_hmac( 'sha256', $ts . '.' . $body, $s['key'] ), $sig ) ) {
			return new WP_Error( 'wp2ss_sig', 'Bad signature — the fleet key on the sending site doesn’t match this hub.', array( 'status' => 401 ) );
		}
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) || empty( $data['site'] ) || ! is_string( $data['site'] ) || ! wp_http_validate_url( esc_url_raw( $data['site'] ) ) && ! filter_var( $data['site'], FILTER_VALIDATE_URL ) ) {
			return new WP_Error( 'wp2ss_body', 'Malformed report.', array( 'status' => 400 ) );
		}
		$key = self::site_key( $data['site'] );
		if ( $key === self::site_key( self::own_url() ) ) {
			return new WP_Error( 'wp2ss_self', 'Reports for the hub’s own address are not accepted.', array( 'status' => 403 ) );
		}
		$pins     = self::pins();
		$site_sig = (string) $req->get_header( 'x_wp2ss_site_signature' );
		$legacy   = false;
		if ( isset( $pins[ $key ] ) ) {
			if ( ! $site_sig || ! hash_equals( hash_hmac( 'sha256', $ts . '.' . $body, $pins[ $key ] ), $site_sig ) ) {
				return new WP_Error( 'wp2ss_identity', 'This address is already registered to a different site. If you reinstalled the scanner there, remove the site from the hub’s list, then report again.', array( 'status' => 403 ) );
			}
		} elseif ( $allow_enroll && isset( $data['enroll'] ) && is_string( $data['enroll'] ) && preg_match( '/^[A-Za-z0-9]{32,64}$/', $data['enroll'] ) ) {
			if ( ! $site_sig || ! hash_equals( hash_hmac( 'sha256', $ts . '.' . $body, $data['enroll'] ), $site_sig ) ) {
				return new WP_Error( 'wp2ss_identity', 'Site signature doesn’t match.', array( 'status' => 401 ) );
			}
			if ( ! isset( self::raw_sites()[ $key ] ) && count( self::raw_sites() ) >= self::MAX_SITES ) {
				return new WP_Error( 'wp2ss_full', 'This hub already tracks the maximum number of sites.', array( 'status' => 507 ) );
			}
			$pins[ $key ] = $data['enroll'];
			update_site_option( self::PINS, $pins );
		} elseif ( $allow_enroll ) {
			$legacy = true; // A version 1.2 member: accepted, but marked, and it can't overwrite a registered site.
		} else {
			return new WP_Error( 'wp2ss_identity', 'This site hasn’t registered with the hub yet. Send a report first.', array( 'status' => 403 ) );
		}
		unset( $data['enroll'] );
		return array( $data, $ts, $legacy, ! isset( self::pins()[ $key ] ) ? false : true );
	}

	private static function pins() {
		$p = get_site_option( self::PINS, array() );
		return is_array( $p ) ? $p : array();
	}

	/** A member checking in: answer whether a new scan was requested. */
	public static function receive_poll( WP_REST_Request $req ) {
		$v = self::verify( $req, false );
		if ( is_wp_error( $v ) ) {
			return $v;
		}
		$key    = self::site_key( $v[0]['site'] );
		$sites  = self::raw_sites();
		$rescan = false;
		if ( isset( $sites[ $key ] ) ) {
			$rescan                 = ! empty( $sites[ $key ]['rescan'] );
			$sites[ $key ]['seen']  = time();
			$sites[ $key ]['rescan'] = 0;
			update_site_option( self::SITES, $sites );
		}
		return rest_ensure_response( array( 'rescan' => $rescan ) );
	}

	public static function receive( WP_REST_Request $req ) {
		$v = self::verify( $req );
		if ( is_wp_error( $v ) ) {
			return $v;
		}
		list( $data, $ts, $legacy, $enrolled ) = $v;
		$stored = self::store( $data, $ts, $legacy );
		if ( is_wp_error( $stored ) ) {
			return $stored;
		}
		return rest_ensure_response( array( 'ok' => true, 'enrolled' => $enrolled ) );
	}

	/** Keep only known fields, as plain text. */
	private static function clean( $d ) {
		$t   = function ( $v, $len = 200 ) {
			return substr( sanitize_text_field( (string) $v ), 0, $len );
		};
		$out = array(
			'site'    => esc_url_raw( (string) $d['site'] ),
			'name'    => $t( isset( $d['name'] ) ? $d['name'] : '', 100 ),
			'admin'   => self::same_host( isset( $d['admin'] ) ? (string) $d['admin'] : '', (string) $d['site'] ),
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
		foreach ( array_slice( isset( $d['serious'] ) && is_array( $d['serious'] ) ? $d['serious'] : array(), 0, 10 ) as $f ) {
			if ( ! is_array( $f ) ) {
				continue;
			}
			$out['serious'][] = array(
				'severity' => in_array( isset( $f['severity'] ) ? $f['severity'] : '', array( 'critical', 'high' ), true ) ? $f['severity'] : 'high',
				'type'     => $t( isset( $f['type'] ) ? $f['type'] : '', 20 ),
				'message'  => $t( isset( $f['message'] ) ? $f['message'] : '', 300 ),
			);
		}
		return $out;
	}

	/** A link to the member's scanner page, only if it's on the member's own host. */
	private static function same_host( $url, $site ) {
		$url = esc_url_raw( $url, array( 'http', 'https' ) );
		$a   = wp_parse_url( $url, PHP_URL_HOST );
		$b   = wp_parse_url( esc_url_raw( $site ), PHP_URL_HOST );
		return $a && $b && strtolower( $a ) === strtolower( $b ) ? $url : '';
	}

	private static function store( $data, $ts = null, $legacy = false ) {
		$d = self::clean( $data );
		if ( ! $d['site'] ) {
			return new WP_Error( 'wp2ss_body', 'Malformed report.', array( 'status' => 400 ) );
		}
		$key   = self::site_key( $d['site'] );
		$sites = self::raw_sites();
		if ( $ts && isset( $sites[ $key ]['ts'] ) && (int) $ts < (int) $sites[ $key ]['ts'] ) {
			return new WP_Error( 'wp2ss_replay', 'Older than the report already stored.', array( 'status' => 409 ) );
		}
		if ( ! isset( $sites[ $key ] ) && count( $sites ) >= self::MAX_SITES ) {
			return new WP_Error( 'wp2ss_full', 'This hub already tracks the maximum number of sites.', array( 'status' => 507 ) );
		}
		$prev          = isset( $sites[ $key ] ) ? $sites[ $key ] : null;
		$d['received'] = time();
		$d['ts']       = $ts ? (int) $ts : time();
		$d['seen']     = time();
		$d['rescan']   = 0;
		$d['overdue']  = 0;
		$d['legacy']   = $legacy ? 1 : 0;
		$sites[ $key ] = $d;
		update_site_option( self::SITES, $sites );
		self::compare( $prev, $d );
		return true;
	}

	/** Same site, however its address was written. */
	public static function site_key( $url ) {
		return md5( strtolower( untrailingslashit( preg_replace( '#^https?://#i', '', trim( (string) $url ) ) ) ) );
	}

	private static function raw_sites() {
		$sites = get_site_option( self::SITES, array() );
		return is_array( $sites ) ? $sites : array();
	}

	/* ------------------------------------------------------------------ */
	/* Hub: alerts                                                         */
	/* ------------------------------------------------------------------ */

	/** Queue an alert if a site got worse, arrived in trouble, or came back after going quiet. */
	private static function compare( $prev, $now ) {
		$bad = $now['verdict'] !== 'CLEAN' && $now['verdict'] !== 'REVIEW';
		if ( ! $prev ) {
			if ( $bad ) {
				self::queue( 'new', $now );
			}
			return;
		}
		$was   = isset( self::RANK[ $prev['verdict'] ] ) ? self::RANK[ $prev['verdict'] ] : 3;
		$fresh = array_diff( wp_list_pluck( $now['serious'], 'message' ), wp_list_pluck( isset( $prev['serious'] ) ? $prev['serious'] : array(), 'message' ) );
		if ( self::RANK[ $now['verdict'] ] < $was ) {
			self::queue( 'worse', $now, array( 'was' => $prev['verdict'], 'fresh' => array_values( $fresh ) ) );
		} elseif ( $fresh && $bad ) {
			self::queue( 'findings', $now, array( 'fresh' => array_values( $fresh ) ) );
		}
		if ( ! empty( $prev['overdue'] ) ) {
			self::queue( 'back', $now );
		}
	}

	private static function queue( $event, $site, $extra = array() ) {
		$s = self::settings();
		if ( ! $s['alert_email'] && ! $s['alert_webhook'] ) {
			return;
		}
		$q   = get_site_option( self::QUEUE, array() );
		$q   = is_array( $q ) ? array_slice( $q, -199 ) : array(); // Bounded, whatever happens.
		$q[] = array_merge(
			array(
				'event'   => $event,
				'site'    => $site['site'],
				'name'    => $site['name'],
				'verdict' => $site['verdict'],
				'label'   => $site['label'],
				'at'      => time(),
			),
			$extra
		);
		update_site_option( self::QUEUE, $q );
		if ( ! wp_next_scheduled( self::ALERT_HOOK ) ) {
			// Collect for a couple of minutes, so a whole fleet scanning at once sends one message.
			wp_schedule_single_event( time() + self::DIGEST_WAIT, self::ALERT_HOOK );
		}
	}

	/** Daily: queue an alert for each site that just became overdue. */
	public static function check_stale() {
		$s = self::settings();
		if ( 'hub' !== $s['mode'] ) {
			return;
		}
		$sites   = self::raw_sites();
		$changed = false;
		$own     = self::site_key( self::own_url() );
		foreach ( $sites as $key => $site ) {
			if ( $key !== $own && empty( $site['overdue'] ) && self::is_stale( $site ) ) {
				$sites[ $key ]['overdue'] = time();
				$changed                  = true;
				if ( $s['alert_stale'] ) {
					self::queue( 'stale', $site, array( 'last' => (int) $site['received'] ) );
				}
			}
		}
		if ( $changed ) {
			update_site_option( self::SITES, $sites );
		}
	}

	/** Plain-text lines for a list of events. */
	private static function digest_lines( $events ) {
		$lines = array();
		$host  = function ( $e ) {
			$h = preg_replace( '#^https?://#i', '', $e['site'] );
			return $e['name'] && $e['name'] !== $h ? $e['name'] . ' (' . $h . ')' : $h;
		};
		foreach ( $events as $e ) {
			$label = $e['label'] ? $e['label'] : WP2SS_Admin::verdict_label( $e['verdict'] );
			switch ( $e['event'] ) {
				case 'worse':
					/* translators: 1: site, 2: new result, 3: old result */
					$lines[] = sprintf( __( '%1$s is now “%2$s” (was “%3$s”).', 'php2shell-scanner' ), $host( $e ), $label, WP2SS_Admin::verdict_label( $e['was'] ) );
					break;
				case 'new':
					/* translators: 1: site, 2: result */
					$lines[] = sprintf( __( '%1$s joined the fleet: “%2$s”.', 'php2shell-scanner' ), $host( $e ), $label );
					break;
				case 'findings':
					/* translators: 1: site, 2: result */
					$lines[] = sprintf( __( '%1$s has new serious findings (“%2$s”).', 'php2shell-scanner' ), $host( $e ), $label );
					break;
				case 'stale':
					/* translators: 1: site, 2: time ago */
					$lines[] = sprintf( __( '%1$s hasn’t reported for %2$s. Its scans may have stopped — or someone switched the scanner off.', 'php2shell-scanner' ), $host( $e ), human_time_diff( (int) $e['last'] ) );
					break;
				case 'back':
					/* translators: 1: site, 2: result */
					$lines[] = sprintf( __( '%1$s is reporting again: “%2$s”.', 'php2shell-scanner' ), $host( $e ), $label );
					break;
				case 'test':
					$lines[] = __( 'This is a test alert from your PHP2Shell Scanner fleet hub. Alerts work.', 'php2shell-scanner' );
					break;
			}
			foreach ( array_slice( isset( $e['fresh'] ) ? $e['fresh'] : array(), 0, 5 ) as $m ) {
				$lines[] = '    - ' . $m;
			}
		}
		return $lines;
	}

	/** Send everything queued as one email and/or one chat message. */
	public static function send_digest() {
		$s = self::settings();
		$q = get_site_option( self::QUEUE, array() );
		delete_site_option( self::QUEUE );
		if ( ! is_array( $q ) || ! $q || 'hub' !== $s['mode'] ) {
			return false;
		}
		// One line per site and event: the latest wins.
		$events = array();
		foreach ( $q as $e ) {
			$events[ self::site_key( $e['site'] ) . '|' . ( 'findings' === $e['event'] ? 'worse' : $e['event'] ) ] = $e;
		}
		$events = array_values( $events );
		usort(
			$events,
			function ( $a, $b ) {
				$r = ( isset( self::RANK[ $a['verdict'] ] ) ? self::RANK[ $a['verdict'] ] : 3 ) - ( isset( self::RANK[ $b['verdict'] ] ) ? self::RANK[ $b['verdict'] ] : 3 );
				return $r ? $r : strcmp( $a['site'], $b['site'] );
			}
		);
		$lines = self::digest_lines( $events );
		$url   = add_query_arg( 'tab', 'fleet', WP2SS_Admin::url() );
		$count = count( $events );
		/* translators: %d: number of sites */
		$subject = 1 === $count && 'test' === $events[0]['event'] ? __( 'PHP2Shell fleet: test alert', 'php2shell-scanner' ) : sprintf( _n( 'PHP2Shell fleet: %d site needs a look', 'PHP2Shell fleet: %d sites need a look', $count, 'php2shell-scanner' ), $count );

		$sent = false;
		if ( $s['alert_email'] ) {
			$plain = function () {
				return 'text/plain'; // Site names and findings come from other sites: never HTML.
			};
			add_filter( 'wp_mail_content_type', $plain, 999 );
			$body = implode( "\n", $lines ) . "\n\n" . __( 'Fleet dashboard:', 'php2shell-scanner' ) . ' ' . $url . "\n\n" . __( 'You get this because fleet alerts are on. Change that on the hub’s Fleet tab.', 'php2shell-scanner' );
			$sent = wp_mail( $s['alert_to'] ? $s['alert_to'] : WP2SS_Settings::alert_email(), $subject, $body ) || $sent;
			remove_filter( 'wp_mail_content_type', $plain, 999 );
		}
		if ( $s['alert_webhook'] ) {
			$sent = self::post_webhook( $s['alert_webhook'], $subject, $lines, $url ) || $sent;
		}
		return $sent;
	}

	/** Slack and Discord incoming webhooks, with anything that could ping or format neutralised. */
	private static function post_webhook( $hook, $subject, $lines, $url ) {
		$discord = (bool) preg_match( '#^https://(?:[a-z]+\.)?discord(?:app)?\.com/#i', $hook );
		$esc     = function ( $t ) use ( $discord ) {
			$t = str_replace( array( '&', '<', '>' ), array( '&amp;', '&lt;', '&gt;' ), $t ); // Slack: no <!channel>, no links.
			return $discord ? str_replace( array( '@', '`' ), array( "@\u{200B}", "'" ), $t ) : $t;
		};
		$text = '*' . $esc( $subject ) . "*\n" . implode( "\n", array_map( $esc, $lines ) ) . "\n" . $url;
		$body = $discord
			? array( 'content' => substr( str_replace( '*', '**', $text ), 0, 1900 ), 'allowed_mentions' => array( 'parse' => array() ) )
			: array( 'text' => substr( $text, 0, 3500 ) );
		$res = wp_safe_remote_post(
			$hook,
			array(
				'timeout' => 8,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( $body ),
			)
		);
		$code = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
		return $code >= 200 && $code < 300;
	}

	/** Send a test alert right away. */
	public static function test_alert() {
		$s = self::settings();
		if ( ! $s['alert_email'] && ! $s['alert_webhook'] ) {
			return new WP_Error( 'wp2ss_no_alerts', __( 'Turn on email alerts or add a webhook first.', 'php2shell-scanner' ) );
		}
		delete_site_option( self::QUEUE );
		self::queue( 'test', array( 'site' => self::own_url(), 'name' => '', 'verdict' => 'CLEAN', 'label' => '' ) );
		wp_clear_scheduled_hook( self::ALERT_HOOK );
		return self::send_digest() ? true : new WP_Error( 'wp2ss_alert_failed', __( 'The test alert couldn’t be sent. Check the email address or webhook, and that this site can send email.', 'php2shell-scanner' ) );
	}

	/** Ask one site (by key) or every site to scan at its next check-in. @return int sites asked */
	public static function request_rescan( $key = null ) {
		$sites = self::raw_sites();
		$n     = 0;
		foreach ( $sites as $k => $site ) {
			if ( null === $key || $k === $key ) {
				$sites[ $k ]['rescan'] = time();
				$n++;
			}
		}
		update_site_option( self::SITES, $sites );
		// The hub itself doesn't need to wait for a check-in.
		$own = self::site_key( self::own_url() );
		if ( ( null === $key || $key === $own ) && isset( $sites[ $own ] ) && ! WP2SS_Scanner::current() ) {
			WP2SS_Scanner::start( WP2SS_Settings::scan_args(), 'cron' );
			wp_schedule_single_event( time() + 5, WP2SS_Cron::STEP_HOOK );
		}
		return $n;
	}

	public static function sites() {
		$sites = self::raw_sites();
		$rank  = self::RANK;
		uasort(
			$sites,
			function ( $a, $b ) use ( $rank ) {
				$c = $rank[ $a['verdict'] ] - $rank[ $b['verdict'] ];
				return $c ? $c : strcmp( $a['site'], $b['site'] );
			}
		);
		return $sites;
	}

	/** Remove a site (and its registration, so it can register again). */
	public static function forget( $key ) {
		$sites = self::raw_sites();
		$pins  = self::pins();
		unset( $sites[ $key ], $pins[ $key ] );
		update_site_option( self::SITES, $sites );
		update_site_option( self::PINS, $pins );
	}

	/** Empty the list. Every site registers again with its next report. */
	public static function clear() {
		delete_site_option( self::SITES );
		delete_site_option( self::PINS );
		delete_site_option( self::QUEUE );
	}

	/** A report is stale if no scan arrived for longer than the hub allows (default: two weekly scans and a day). */
	public static function is_stale( $site ) {
		return time() - (int) $site['received'] > (int) self::settings()['stale_days'] * DAY_IN_SECONDS;
	}
}
