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

// The step lock and cached core checksums.
global $wpdb;
$wp2ss_table = is_multisite() ? $wpdb->get_blog_prefix( get_main_site_id() ) . 'options' : $wpdb->options;
$wpdb->query( $wpdb->prepare( "DELETE FROM `$wp2ss_table` WHERE option_name = %s", 'wp2ss_lock' ) ); // phpcs:ignore
foreach ( array( $wpdb->options, $wpdb->sitemeta ) as $wp2ss_t ) {
	if ( ! $wp2ss_t || ( $wp2ss_t === $wpdb->sitemeta && ! is_multisite() ) ) {
		continue;
	}
	$wp2ss_col = $wp2ss_t === $wpdb->sitemeta ? 'meta_key' : 'option_name';
	$wpdb->query( $wpdb->prepare( "DELETE FROM `$wp2ss_t` WHERE $wp2ss_col LIKE %s", '%' . $wpdb->esc_like( 'wp2ss_core_' ) . '%' ) ); // phpcs:ignore
}
