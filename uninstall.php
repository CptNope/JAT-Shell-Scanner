<?php
/**
 * Remove everything the plugin stored.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

foreach ( array( 'wp2ss_job', 'wp2ss_report', 'wp2ss_ignored', 'wp2ss_settings' ) as $opt ) {
	delete_site_option( $opt );
}
delete_site_transient( 'wp2ss_release' );
delete_metadata( 'user', 0, 'wp2ss_dismissed', '', true );
wp_clear_scheduled_hook( 'wp2ss_scheduled_scan' );
wp_clear_scheduled_hook( 'wp2ss_scan_step' );
