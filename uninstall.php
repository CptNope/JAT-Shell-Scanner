<?php
/**
 * Remove everything the plugin stored.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

foreach ( array( 'wp2ss_job', 'wp2ss_report', 'wp2ss_ignored', 'wp2ss_settings', 'wp2ss_env', 'wp2ss_admins' ) as $wp2ss_opt ) {
	delete_site_option( $wp2ss_opt );
}
delete_site_transient( 'wp2ss_release' );
delete_metadata( 'user', 0, 'wp2ss_dismissed', '', true );

// Scheduled events (on multisite they live on the main site).
if ( is_multisite() ) {
	switch_to_blog( get_main_site_id() );
}
wp_clear_scheduled_hook( 'wp2ss_scheduled_scan' );
wp_clear_scheduled_hook( 'wp2ss_scan_step' );
if ( is_multisite() ) {
	restore_current_blog();
}

// The step lock, cached core checksums and release manifests.
$wp2ss_table = is_multisite() ? $wpdb->get_blog_prefix( get_main_site_id() ) . 'options' : $wpdb->options;
$wpdb->query( $wpdb->prepare( "DELETE FROM `$wp2ss_table` WHERE option_name = %s", 'wp2ss_lock' ) ); // phpcs:ignore
foreach ( array( 'wp2ss_core_', 'wp2ss_manifest_' ) as $wp2ss_prefix ) {
	$wp2ss_like = '%' . $wpdb->esc_like( $wp2ss_prefix ) . '%';
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wp2ss_like ) ); // phpcs:ignore
	if ( is_multisite() ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s", $wp2ss_like ) ); // phpcs:ignore
	}
}
