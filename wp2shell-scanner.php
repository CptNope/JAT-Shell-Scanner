<?php
/**
 * Plugin Name:       Anderson Shell Scanner
 * Plugin URI:        https://jeremyanderson.tech/project/php2shell-wp2shell-scanner/
 * Description:       Checks whether your site is exposed to — or was broken into through — PHP2Shell (CVE-2026-109618 / CVE-2026-109619, critical bugs in PHP itself) and wp2shell (CVE-2026-63030 / CVE-2026-60137, a WordPress core bug). Looks at your PHP and WordPress versions, webshells, rogue admins, changed files and server logs. Scans only read; one-click fixes (quarantine, removing admin rights) are optional and can be undone. Includes a self-hosted fleet dashboard for many sites, with alerts.
 * Version:           1.5.0
 * Requires at least: 6.0
 * Requires PHP:      7.0
 * Author:            Jeremy Anderson
 * Author URI:        https://jeremyanderson.tech
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * Text Domain:       anderson-shell-scanner
 * Domain Path:       /languages
 * Network:           true
 * Update URI:        https://github.com/CptNope/PHP2Shell-WP-scanner
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( defined( 'WP2SS_VERSION' ) ) {
	return; // Another copy is already loaded (e.g. installed twice under different folder names).
}

define( 'WP2SS_VERSION', '1.5.0' );
define( 'WP2SS_FILE', __FILE__ );
define( 'WP2SS_DIR', plugin_dir_path( __FILE__ ) );
define( 'WP2SS_URL', plugin_dir_url( __FILE__ ) );
define( 'WP2SS_BASENAME', plugin_basename( __FILE__ ) );
define( 'WP2SS_REPO', 'CptNope/PHP2Shell-WP-scanner' );
define( 'WP2SS_WPORG_SLUG', 'anderson-shell-scanner' );
define( 'WP2SS_AUTHOR_URL', 'https://jeremyanderson.tech/' );
define( 'WP2SS_DOCS_URL', WP2SS_AUTHOR_URL . 'project/php2shell-wp2shell-scanner/' );

/*
 * Two builds come from this source. The GitHub release zip ships
 * includes/class-updater.php and updates itself from GitHub releases. The
 * WordPress.org build leaves that file out (WordPress.org plugins must only
 * update through WordPress.org) and checks its own files against
 * WordPress.org's published checksums instead.
 */
define( 'WP2SS_CHANNEL', file_exists( WP2SS_DIR . 'includes/class-updater.php' ) ? 'github' : 'wporg' );

require_once WP2SS_DIR . 'includes/class-scanner.php';
require_once WP2SS_DIR . 'includes/class-env.php';
require_once WP2SS_DIR . 'includes/class-settings.php';
require_once WP2SS_DIR . 'includes/class-cron.php';
require_once WP2SS_DIR . 'includes/class-admin.php';
require_once WP2SS_DIR . 'includes/class-site-health.php';
if ( 'github' === WP2SS_CHANNEL ) {
	require_once WP2SS_DIR . 'includes/class-updater.php';
}
require_once WP2SS_DIR . 'includes/class-fixes.php';
require_once WP2SS_DIR . 'includes/class-fleet.php';

add_action(
	'plugins_loaded',
	function () {
		if ( 'github' === WP2SS_CHANNEL ) {
			// WordPress.org loads translations for directory plugins by itself.
			load_plugin_textdomain( 'anderson-shell-scanner', false, dirname( WP2SS_BASENAME ) . '/languages' ); // phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- GitHub edition only.
		}

		WP2SS_Env::init();
		WP2SS_Cron::init();
		if ( 'github' === WP2SS_CHANNEL ) {
			WP2SS_Updater::init();
		}
		WP2SS_Fleet::init();

		if ( is_admin() ) {
			WP2SS_Admin::init();
			WP2SS_Site_Health::init();
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			require_once WP2SS_DIR . 'includes/class-cli.php';
			WP_CLI::add_command( 'php2shell', 'WP2SS_CLI' );
			WP_CLI::add_command( 'wp2shell', 'WP2SS_CLI' ); // Name used by version 1.0.
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
		WP2SS_Fleet::unschedule();
		WP2SS_Scanner::cancel();
	}
);
