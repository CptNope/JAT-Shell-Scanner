<?php
/**
 * Scheduled scans and email alerts.
 *
 * WP-Cron runs inside normal web requests, which have short time limits on
 * many hosts. So a scheduled scan does one slice of work, then queues the next
 * slice a few seconds later, until it's finished.
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

	public static function schedules( $s ) {
		if ( ! isset( $s['weekly'] ) ) {
			$s['weekly'] = array( 'interval' => WEEK_IN_SECONDS, 'display' => __( 'Once Weekly', 'wp2shell-scanner' ) );
		}
		return $s;
	}

	public static function ensure() {
		$s = WP2SS_Settings::get();
		if ( 'off' !== $s['schedule'] && ! wp_next_scheduled( self::HOOK ) ) {
			self::reschedule( $s['schedule'] );
		}
	}

	public static function reschedule( $schedule ) {
		wp_clear_scheduled_hook( self::HOOK );
		if ( 'off' !== $schedule ) {
			// First run within the hour, spread out so many sites on one server don't all fire at once.
			wp_schedule_event( time() + wp_rand( 300, HOUR_IN_SECONDS ), $schedule, self::HOOK );
		}
	}

	public static function unschedule() {
		wp_clear_scheduled_hook( self::HOOK );
		wp_clear_scheduled_hook( self::STEP_HOOK );
	}

	public static function run() {
		if ( WP2SS_Scanner::current() ) {
			return; // Something is already scanning.
		}
		WP2SS_Scanner::start( WP2SS_Settings::scan_args(), 'cron' );
		self::step();
	}

	public static function step() {
		$max    = (int) ini_get( 'max_execution_time' );
		$budget = $max > 0 ? max( 5, min( 20, $max / 2 ) ) : 20;
		$r      = WP2SS_Scanner::step( $budget );
		if ( is_array( $r ) && empty( $r['verdict'] ) && ! wp_next_scheduled( self::STEP_HOOK ) ) {
			wp_schedule_single_event( time() + 5, self::STEP_HOOK );
			if ( function_exists( 'spawn_cron' ) ) {
				spawn_cron();
			}
		}
	}

	/** Email when a scheduled scan has findings that weren't in the last report. */
	public static function maybe_alert( $report, $previous ) {
		$s = WP2SS_Settings::get();
		if ( 'cron' !== $report['source'] || ! $s['email'] ) {
			return;
		}
		$ignored = (array) get_site_option( 'wp2ss_ignored', array() );
		$verdict = WP2SS_Scanner::verdict( $report['findings'], $ignored );
		if ( ! in_array( $verdict, array( 'COMPROMISED', 'SUSPICIOUS', 'VULNERABLE' ), true ) ) {
			return;
		}

		$old = $previous ? wp_list_pluck( $previous['findings'], 'id' ) : array();
		$new = array();
		foreach ( $report['findings'] as $f ) {
			if ( WP2SS_Scanner::sev_rank( $f['severity'] ) >= 4 && ! isset( $ignored[ $f['id'] ] ) && ! in_array( $f['id'], $old, true ) ) {
				$new[] = $f;
			}
		}
		if ( ! $new ) {
			return; // Already told them about everything.
		}

		$site    = wp_specialchars_decode( get_site_option( 'site_name', get_bloginfo( 'name' ) ), ENT_QUOTES );
		$subject = sprintf( /* translators: 1: verdict, 2: site name */ __( '[%2$s] wp2shell Scanner: %1$s', 'wp2shell-scanner' ), WP2SS_Admin::verdict_label( $verdict ), $site );

		$lines   = array();
		$lines[] = sprintf( /* translators: %s: site URL */ __( 'A scheduled scan of %s found new problems:', 'wp2shell-scanner' ), $report['site'] );
		$lines[] = '';
		foreach ( array_slice( $new, 0, 20 ) as $f ) {
			$lines[] = '• [' . strtoupper( $f['severity'] ) . '] ' . $f['message'];
			if ( $f['advice'] ) {
				$lines[] = '  ' . $f['advice'];
			}
		}
		if ( count( $new ) > 20 ) {
			$lines[] = sprintf( /* translators: %d: count */ __( '…and %d more.', 'wp2shell-scanner' ), count( $new ) - 20 );
		}
		$lines[] = '';
		$lines[] = __( 'See the full report:', 'wp2shell-scanner' ) . ' ' . WP2SS_Admin::url();
		$lines[] = '';
		$lines[] = __( 'You get this email because automatic scans and alerts are on. Change that on the scanner page.', 'wp2shell-scanner' );

		wp_mail( WP2SS_Settings::alert_email(), $subject, implode( "\n", $lines ) );
	}
}
