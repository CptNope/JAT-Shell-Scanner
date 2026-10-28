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

require_once plugin_dir_path( __FILE__ ) . 'includes/class-paths.php';

/**
 * Delete a folder of the plugin's and everything in it (without following links).
 *
 * @param string $dir Folder.
 */
function wp2ss_uninstall_rmdir( $dir ) {
	if ( ! $dir || ! is_dir( $dir ) || is_link( $dir ) ) {
		return;
	}
	$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
	foreach ( $it as $f ) {
		$f->isDir() && ! $f->isLink() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir, WordPress.WP.AlternativeFunctions.unlink_unlink -- The plugin's own quarantine folder.
	}
	@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
}

// The quarantine holds files that were flagged as malicious: remove it with the plugin.
// It lives in the plugin's folder in the main site's uploads.
if ( is_multisite() ) {
	switch_to_blog( get_main_site_id() );
}
$wp2ss_uploads = wp_upload_dir( null, false );
if ( is_multisite() ) {
	restore_current_blog();
}
if ( ! empty( $wp2ss_uploads['basedir'] ) ) {
	wp2ss_uninstall_rmdir( wp_normalize_path( untrailingslashit( $wp2ss_uploads['basedir'] ) ) . '/jat-shell-scanner' );
}
// Builds before 1.6 kept it in the content folder.
$wp2ss_qname = get_site_option( 'wp2ss_quarantine_dir' );
if ( $wp2ss_qname && preg_match( '/^wp2ss-quarantine-[a-z0-9]{16}$/', $wp2ss_qname ) ) {
	wp2ss_uninstall_rmdir( WP2SS_Paths::content() . '/' . $wp2ss_qname );
}

foreach ( array( 'wp2ss_job', 'wp2ss_report', 'wp2ss_ignored', 'wp2ss_settings', 'wp2ss_env', 'wp2ss_admins', 'wp2ss_fixes', 'wp2ss_quarantine_folder', 'wp2ss_quarantine_dir', 'wp2ss_fleet', 'wp2ss_fleet_sites', 'wp2ss_fleet_status', 'wp2ss_fleet_queue', 'wp2ss_fleet_pins' ) as $wp2ss_opt ) {
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
foreach ( array( 'wp2ss_fleet_alerts', 'wp2ss_fleet_daily', 'wp2ss_fleet_poll' ) as $wp2ss_hook ) {
	wp_clear_scheduled_hook( $wp2ss_hook );
}
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
