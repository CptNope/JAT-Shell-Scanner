<?php
/**
 * Plugin Name:       wp2shell Scanner
 * Description:       Read-only scan for signs of wp2shell (CVE-2026-63030 / CVE-2026-60137) exploitation: vulnerable core version, dropped webshell plugins, PHP in cache/uploads, rogue admins, modified core files and access-log markers. Never changes or deletes anything.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Jeremy Anderson
 * License:           MIT
 * Plugin URI:        https://github.com/CptNope/PHP2Shell-WP-scanner
 * Text Domain:       wp2shell-scanner
 * Network:           true
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WP2SS_VERSION', '1.0.0' );
define( 'WP2SS_OPTION', 'wp2ss_last_report' );

require_once __DIR__ . '/includes/class-scanner.php';

/* -------------------------------------------------------------------------- */
/* Admin screen: Tools → wp2shell Scanner                                     */
/* -------------------------------------------------------------------------- */

add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', 'wp2ss_menu' );
function wp2ss_menu() {
	$parent = is_multisite() ? 'settings.php' : 'tools.php';
	add_submenu_page( $parent, 'wp2shell Scanner', 'wp2shell Scanner', 'manage_options', 'wp2shell-scanner', 'wp2ss_page' );
}

add_action( 'admin_post_wp2ss_scan', 'wp2ss_handle_scan' );
function wp2ss_handle_scan() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Not allowed.' );
	}
	check_admin_referer( 'wp2ss_scan' );

	$log    = isset( $_POST['log'] ) ? sanitize_text_field( wp_unslash( $_POST['log'] ) ) : '';
	$core   = ! empty( $_POST['core'] );
	$report = ( new WP2Shell_Scanner() )->run( array( 'log' => $log, 'core' => $core ) );

	update_site_option( WP2SS_OPTION, $report );

	$back = is_multisite() ? network_admin_url( 'settings.php?page=wp2shell-scanner' ) : admin_url( 'tools.php?page=wp2shell-scanner' );
	wp_safe_redirect( add_query_arg( 'scanned', 1, $back ) );
	exit;
}

add_action( 'admin_post_wp2ss_export', 'wp2ss_handle_export' );
function wp2ss_handle_export() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Not allowed.' );
	}
	check_admin_referer( 'wp2ss_export' );
	$report = get_site_option( WP2SS_OPTION );
	nocache_headers();
	header( 'Content-Type: application/json' );
	header( 'Content-Disposition: attachment; filename="wp2shell-scan-' . sanitize_file_name( wp_parse_url( home_url(), PHP_URL_HOST ) ) . '-' . gmdate( 'Ymd-His' ) . '.json"' );
	echo wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
	exit;
}

function wp2ss_page() {
	$report = get_site_option( WP2SS_OPTION );
	$colors = array(
		'critical' => '#b32d2e',
		'high'     => '#d63638',
		'medium'   => '#dba617',
		'low'      => '#2271b1',
		'info'     => '#646970',
	);
	$verdict_colors = array(
		'COMPROMISED' => '#b32d2e',
		'SUSPICIOUS'  => '#d63638',
		'REVIEW'      => '#dba617',
		'CLEAN'       => '#00a32a',
	);
	?>
	<div class="wrap">
		<h1>wp2shell Scanner</h1>
		<p>Checks this site for signs of the <strong>wp2shell</strong> WordPress core exploit (CVE-2026-63030 + CVE-2026-60137). The scan is read-only — nothing is changed or deleted.</p>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="background:#fff;border:1px solid #c3c4c7;padding:16px;max-width:720px">
			<?php wp_nonce_field( 'wp2ss_scan' ); ?>
			<input type="hidden" name="action" value="wp2ss_scan">
			<p><label><input type="checkbox" name="core" value="1" checked> Verify core files against wordpress.org checksums</label></p>
			<p>
				<label for="wp2ss-log"><strong>Access log path</strong> (optional)</label><br>
				<input type="text" id="wp2ss-log" name="log" class="regular-text code" placeholder="/var/log/nginx/access.log">
				<br><span class="description">If PHP can read your server log, the scan will look for successful batch-API hits, exploit user-agents and known attacker IPs. .gz files work.</span>
			</p>
			<?php submit_button( 'Run scan', 'primary', 'submit', false ); ?>
			<span class="description" style="margin-left:8px">Large sites: use <code>wp wp2shell scan</code> to avoid timeouts.</span>
		</form>

		<?php if ( $report ) : ?>
			<h2 style="margin-top:28px">
				Last scan:
				<span style="background:<?php echo esc_attr( $verdict_colors[ $report['verdict'] ] ); ?>;color:#fff;padding:3px 10px;border-radius:3px;font-size:14px"><?php echo esc_html( $report['verdict'] ); ?></span>
			</h2>
			<p>
				<?php echo esc_html( $report['scanned'] ); ?> ·
				WordPress <?php echo esc_html( $report['wp'] ); ?> ·
				<?php echo (int) $report['stats']['files_scanned']; ?> PHP files ·
				<?php echo esc_html( $report['stats']['duration'] ); ?>s
				· <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wp2ss_export' ), 'wp2ss_export' ) ); ?>">Download JSON</a>
			</p>

			<table class="widefat striped">
				<thead><tr><th style="width:90px">Severity</th><th style="width:90px">Type</th><th>Finding</th><th>What to do</th></tr></thead>
				<tbody>
				<?php foreach ( $report['findings'] as $f ) : ?>
					<tr>
						<td><span style="color:<?php echo esc_attr( $colors[ $f['severity'] ] ); ?>;font-weight:600;text-transform:uppercase"><?php echo esc_html( $f['severity'] ); ?></span></td>
						<td><?php echo esc_html( $f['type'] ); ?></td>
						<td><?php echo esc_html( $f['message'] ); ?>
							<?php if ( $f['location'] ) : ?><br><code style="font-size:11px"><?php echo esc_html( $f['location'] ); ?></code><?php endif; ?>
						</td>
						<td><?php echo esc_html( $f['advice'] ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>

			<?php if ( in_array( $report['verdict'], array( 'COMPROMISED', 'SUSPICIOUS' ), true ) ) : ?>
				<div class="notice notice-error inline" style="margin-top:16px"><p>
					<strong>If this site is compromised:</strong> take a full backup (files + DB) for evidence first, update WordPress, remove the flagged files/plugins/users,
					reset every admin password, rotate the database password and the salts in <code>wp-config.php</code>, and check for persistence (cron jobs, mu-plugins, <code>.htaccess</code>).
				</p></div>
			<?php endif; ?>
		<?php endif; ?>
	</div>
	<?php
}

/* -------------------------------------------------------------------------- */
/* WP-CLI: wp wp2shell scan                                                    */
/* -------------------------------------------------------------------------- */

if ( defined( 'WP_CLI' ) && WP_CLI ) {

	/**
	 * Scan for signs of wp2shell exploitation.
	 */
	class WP2SS_CLI {

		/**
		 * Run a scan.
		 *
		 * ## OPTIONS
		 *
		 * [--log=<path>]
		 * : Access log to check for exploitation markers (.gz ok).
		 *
		 * [--skip-core]
		 * : Skip the wordpress.org core checksum check.
		 *
		 * [--min=<severity>]
		 * : Only show findings at or above this level.
		 * ---
		 * default: low
		 * options:
		 *   - info
		 *   - low
		 *   - medium
		 *   - high
		 *   - critical
		 * ---
		 *
		 * [--format=<format>]
		 * : Output format.
		 * ---
		 * default: table
		 * options:
		 *   - table
		 *   - json
		 *   - csv
		 *   - summary
		 * ---
		 *
		 * ## EXAMPLES
		 *
		 *     wp wp2shell scan
		 *     wp wp2shell scan --log=/var/log/nginx/access.log
		 *     wp wp2shell scan --format=summary
		 *     wp @all wp2shell scan --format=summary
		 *
		 * Exit code: 0 clean/review, 1 suspicious, 2 compromised.
		 *
		 * @when after_wp_load
		 */
		public function scan( $args, $assoc ) {
			$report = ( new WP2Shell_Scanner() )->run(
				array(
					'log'  => isset( $assoc['log'] ) ? $assoc['log'] : '',
					'core' => empty( $assoc['skip-core'] ),
				)
			);
			update_site_option( WP2SS_OPTION, $report );

			$min      = WP2Shell_Scanner::sev_rank( isset( $assoc['min'] ) ? $assoc['min'] : 'low' );
			$findings = array_values(
				array_filter(
					$report['findings'],
					function ( $f ) use ( $min ) {
						return WP2Shell_Scanner::sev_rank( $f['severity'] ) >= $min;
					}
				)
			);
			$format = isset( $assoc['format'] ) ? $assoc['format'] : 'table';

			if ( 'json' === $format ) {
				$report['findings'] = $findings;
				WP_CLI::line( wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			} elseif ( 'summary' === $format ) {
				$c = array_count_values( wp_list_pluck( $report['findings'], 'severity' ) );
				WP_CLI::line(
					sprintf(
						'%-12s %-40s wp %-7s crit:%d high:%d med:%d',
						$report['verdict'],
						$report['site'],
						$report['wp'],
						isset( $c['critical'] ) ? $c['critical'] : 0,
						isset( $c['high'] ) ? $c['high'] : 0,
						isset( $c['medium'] ) ? $c['medium'] : 0
					)
				);
			} else {
				if ( $findings ) {
					WP_CLI\Utils\format_items( $format, $findings, array( 'severity', 'type', 'message', 'location' ) );
				}
				$line = "{$report['site']} — {$report['verdict']} ({$report['stats']['files_scanned']} PHP files, {$report['stats']['duration']}s)";
				'CLEAN' === $report['verdict'] || 'REVIEW' === $report['verdict'] ? WP_CLI::success( $line ) : WP_CLI::warning( $line );
			}

			if ( 'COMPROMISED' === $report['verdict'] ) {
				WP_CLI::halt( 2 );
			} elseif ( 'SUSPICIOUS' === $report['verdict'] ) {
				WP_CLI::halt( 1 );
			}
		}
	}

	WP_CLI::add_command( 'wp2shell', 'WP2SS_CLI' );
}

/* Clean up stored report on uninstall. */
register_uninstall_hook( __FILE__, 'wp2ss_uninstall' );
function wp2ss_uninstall() {
	delete_site_option( WP2SS_OPTION );
}
