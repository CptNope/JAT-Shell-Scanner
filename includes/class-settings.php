<?php
/**
 * Settings storage.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Settings {

	const OPTION = 'wp2ss_settings';

	public static function defaults() {
		return array(
			'schedule' => 'weekly',
			'email'    => true,
			'email_to' => '',
			'core'     => true,
			'log'      => '',
		);
	}

	public static function get() {
		return wp_parse_args( (array) get_site_option( self::OPTION, array() ), self::defaults() );
	}

	public static function save( $new ) {
		$s = self::defaults();
		if ( in_array( $new['schedule'], array( 'off', 'daily', 'weekly' ), true ) ) {
			$s['schedule'] = $new['schedule'];
		}
		$s['email']    = (bool) $new['email'];
		$s['email_to'] = is_email( $new['email_to'] ) ? $new['email_to'] : '';
		$s['core']     = (bool) $new['core'];
		$s['log']      = trim( (string) $new['log'] );

		update_site_option( self::OPTION, $s );
		WP2SS_Cron::reschedule( $s['schedule'] );
		return $s;
	}

	/** Arguments for a scan, from settings. */
	public static function scan_args() {
		$s = self::get();
		return array(
			'core' => $s['core'],
			'log'  => $s['log'],
		);
	}

	public static function alert_email() {
		$s = self::get();
		return $s['email_to'] ? $s['email_to'] : get_site_option( 'admin_email' );
	}
}
