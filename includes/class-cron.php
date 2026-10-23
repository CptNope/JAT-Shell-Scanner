<?php
/**
 * Scheduled scans and email alerts.
 *
 * WP-Cron runs inside normal web requests, which have short time limits on
 * many hosts. So a scheduled scan works for as long as the request safely can,
 * then queues the next slice, until it's finished. On a quiet site the next
 * slice may only run at the next visit (or the next system-cron tick); the job
 * simply waits — it's only abandoned after a full day with no progress.
 *
 * On multisite, only the main site schedules scans (one scan covers the network).
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Cron {

	const HOOK      = 'wp2ss_scheduled_scan';
	const STEP_HOOK = 'wp2ss_scan_step';

	public static function init() {
		add_action( self::HOOK, array( __CLASS__, 'run' ) );
		add_action( self::STEP_HOOK, array( __CLASS__, 'step' ) );
		add_action( 'wp2ss_scan_complete', array( __CLASS__, 'maybe_alert' ), 10, 2 );
		add_filter( 'cron_schedules', array( __CLASS__, 'schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval

		// Self-heal: if the event went missing (e.g. a migration), put it back.
		add_action( 'admin_init', array( __CLASS__, 'ensure' ) );
	}

	/** Scans are scheduled on one site only. */
	private static function in_charge() {
		return ! is_multisite() || is_main_site();
	}

	public static function schedules( $s ) {
		if ( ! isset( $s['weekly'] ) ) {
			$s['weekly'] = array( 'interval' => WEEK_IN_SECONDS, 'display' => __( 'Once Weekly', 'php2shell-scanner' ) );
		}
		return $s;
	}

	public static function ensure() {
		if ( ! self::in_charge() ) {
			return;
		}
		$s = WP2SS_Settings::get();
		if ( 'off' !== $s['schedule'] && ! wp_next_scheduled( self::HOOK ) ) {
			self::reschedule( $s['schedule'] );
		}
		// A scheduled scan whose next slice went missing (cron event lost, site migrated…): queue it again.
		$job = WP2SS_Scanner::current();
		if ( $job && 'cron' === $job['source'] && time() - (int) $job['updated'] > 5 * MINUTE_IN_SECONDS && ! wp_next_scheduled( self::STEP_HOOK ) ) {
			wp_schedule_single_event( time() + 5, self::STEP_HOOK );
		}
	}

	public static function reschedule( $schedule ) {
		if ( is_multisite() && ! is_main_site() ) {
			switch_to_blog( get_main_site_id() );
			self::reschedule( $schedule );
			restore_current_blog();
			return;
		}
		wp_clear_scheduled_hook( self::HOOK );
		if ( 'off' !== $schedule ) {
			// First run within the hour, spread out so many sites on one server don't all fire at once.
			wp_schedule_event( time() + wp_rand( 300, HOUR_IN_SECONDS ), $schedule, self::HOOK );
		}
	}

	public static function unschedule() {
		$clear = function () {
			wp_clear_scheduled_hook( WP2SS_Cron::HOOK );
			wp_clear_scheduled_hook( WP2SS_Cron::STEP_HOOK );
		};
		$clear();
		if ( is_multisite() && ! is_main_site() ) {
			switch_to_blog( get_main_site_id() );
			$clear();
			restore_current_blog();
		}
	}

	public static function run() {
		if ( ! self::in_charge() ) {
			return;
		}
		if ( ! WP2SS_Scanner::current() ) {
			WP2SS_Scanner::start( WP2SS_Settings::scan_args(), 'cron' );
		}
		self::step(); // If a scan is already in progress, help it along instead of starting over.
	}

	/** Seconds this cron request may spend: generous with no limit (real server cron, CLI). */
	public static function budget() {
		$max = (int) ini_get( 'max_execution_time' );
		if ( 0 === $max || 'cli' === PHP_SAPI ) {
			return 120;
		}
		return max( 5, min( 25, $max * 0.6 ) );
	}

	public static function step() {
		if ( ! self::in_charge() ) {
			return;
		}
		// Use the whole budget of this request, slice after slice.
		$until = microtime( true ) + self::budget();
		do {
			$left = $until - microtime( true );
			$r    = WP2SS_Scanner::step( max( 1, $left ) );
		} while ( is_array( $r ) && empty( $r['verdict'] ) && empty( $r['busy'] ) && microtime( true ) < $until - 1 );

		if ( is_array( $r ) && empty( $r['verdict'] ) && ! wp_next_scheduled( self::STEP_HOOK ) ) {
			// Busy means another request is mid-slice; check back a little later.
			wp_schedule_single_event( time() + ( empty( $r['busy'] ) ? 5 : 30 ), self::STEP_HOOK );
		}
	}

	/** Email when a scheduled scan finds serious problems that weren't in the last report. */
	public static function maybe_alert( $report, $previous ) {
		$s = WP2SS_Settings::get();
		if ( 'cron' !== $report['source'] || ! $s['email'] ) {
			return;
		}
		$ignored = WP2SS_Scanner::ignored();
		$verdict = WP2SS_Scanner::verdict( $report['findings'], $ignored );
		if ( ! in_array( $verdict, array( 'COMPROMISED', 'SUSPICIOUS', 'VULNERABLE' ), true ) ) {
			return;
		}

		$old = $previous ? wp_list_pluck( $previous['findings'], 'id' ) : array();
		$new = array();
		foreach ( $report['findings'] as $f ) {
			if ( WP2SS_Scanner::sev_rank( $f['severity'] ) >= 4 && ! WP2SS_Scanner::is_ignored( $f, $ignored ) && ! in_array( $f['id'], $old, true ) ) {
				$new[] = $f;
			}
		}
		if ( ! $new ) {
			return; // Already told them about everything.
		}

		$site    = wp_specialchars_decode( get_site_option( 'site_name', get_bloginfo( 'name' ) ), ENT_QUOTES );
		$subject = sprintf( /* translators: 1: verdict, 2: site name */ __( '[%2$s] PHP2Shell Scanner: %1$s', 'php2shell-scanner' ), WP2SS_Admin::verdict_label( $verdict, $report['findings'] ), $site );

		$lines   = array();
		$lines[] = sprintf( /* translators: %s: site URL */ __( 'A scheduled scan of %s found new problems:', 'php2shell-scanner' ), $report['site'] );
		$lines[] = '';
		foreach ( array_slice( $new, 0, 20 ) as $f ) {
			$lines[] = '- [' . strtoupper( $f['severity'] ) . '] ' . wp_strip_all_tags( $f['message'] );
			if ( $f['advice'] ) {
				$lines[] = '  ' . wp_strip_all_tags( $f['advice'] );
			}
		}
		if ( count( $new ) > 20 ) {
			$lines[] = sprintf( /* translators: %d: count */ __( '...and %d more.', 'php2shell-scanner' ), count( $new ) - 20 );
		}
		$lines[] = '';
		$lines[] = __( 'See the full report:', 'php2shell-scanner' ) . ' ' . WP2SS_Admin::url();
		$lines[] = '';
		$lines[] = __( 'You get this email because automatic scans and alerts are on. Change that on the scanner page.', 'php2shell-scanner' );

		// Force plain text: file names and user names in findings come from the attacker.
		$plain = function () {
			return 'text/plain';
		};
		add_filter( 'wp_mail_content_type', $plain, 999 );
		wp_mail( WP2SS_Settings::alert_email(), $subject, implode( "\n", $lines ) );
		remove_filter( 'wp_mail_content_type', $plain, 999 );
	}
}
