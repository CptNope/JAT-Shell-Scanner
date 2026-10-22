<?php
/**
 * Plugin Name:       wp2shell Scanner
 * Plugin URI:        https://github.com/CptNope/PHP2Shell-WP-scanner
 * Description:       Checks your site for signs of the wp2shell attack on WordPress core (CVE-2026-63030 / CVE-2026-60137): vulnerable versions, webshell plugins and files, rogue admins, modified core files and exploit traffic. Read-only — it never changes or deletes anything.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Jeremy Anderson
 * Author URI:        https://jeremyanderson.tech
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * Text Domain:       wp2shell-scanner
 * Network:           true
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( defined( 'WP2SS_VERSION' ) ) {
	return; // Another copy is already loaded (e.g. installed twice under different folder names).
}

define( 'WP2SS_VERSION', '1.0.0' );
define( 'WP2SS_FILE', __FILE__ );
define( 'WP2SS_DIR', plugin_dir_path( __FILE__ ) );
define( 'WP2SS_URL', plugin_dir_url( __FILE__ ) );
define( 'WP2SS_BASENAME', plugin_basename( __FILE__ ) );

require_once WP2SS_DIR . 'includes/class-scanner.php';
require_once WP2SS_DIR . 'includes/class-settings.php';
require_once WP2SS_DIR . 'includes/class-cron.php';
require_once WP2SS_DIR . 'includes/class-admin.php';
require_once WP2SS_DIR . 'includes/class-site-health.php';
require_once WP2SS_DIR . 'includes/class-updater.php';

add_action(
	'plugins_loaded',
	function () {
		load_plugin_textdomain( 'wp2shell-scanner', false, dirname( WP2SS_BASENAME ) . '/languages' );

		WP2SS_Cron::init();
		WP2SS_Updater::init();

		if ( is_admin() ) {
			WP2SS_Admin::init();
			WP2SS_Site_Health::init();
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			require_once WP2SS_DIR . 'includes/class-cli.php';
			WP_CLI::add_command( 'wp2shell', 'WP2SS_CLI' );
		}
	}
);

register_activation_hook(
	__FILE__,
	function () {
		$s = WP2SS_Settings::get();
		WP2SS_Cron::reschedule( $s['schedule'] );
	}
);

register_deactivation_hook(
	__FILE__,
	function () {
		WP2SS_Cron::unschedule();
		WP2SS_Scanner::cancel();
	}
);
