<?php
/**
 * Admin screen, settings, AJAX scanning, ignore list and notices.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Admin {

	const SLUG = 'wp2shell-scanner';

	public static function init() {
		add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( is_multisite() ? 'network_admin_notices' : 'admin_notices', array( __CLASS__, 'notice' ) );
		add_filter( is_multisite() ? 'network_admin_plugin_action_links_' . WP2SS_BASENAME : 'plugin_action_links_' . WP2SS_BASENAME, array( __CLASS__, 'action_links' ) );

		add_action( 'wp_ajax_wp2ss_start', array( __CLASS__, 'ajax_start' ) );
		add_action( 'wp_ajax_wp2ss_step', array( __CLASS__, 'ajax_step' ) );
		add_action( 'wp_ajax_wp2ss_cancel', array( __CLASS__, 'ajax_cancel' ) );
		add_action( 'wp_ajax_wp2ss_ignore', array( __CLASS__, 'ajax_ignore' ) );
		add_action( 'wp_ajax_wp2ss_dismiss', array( __CLASS__, 'ajax_dismiss' ) );

		add_action( 'admin_post_wp2ss_scan', array( __CLASS__, 'post_scan' ) );
		add_action( 'admin_post_wp2ss_export', array( __CLASS__, 'post_export' ) );
		add_action( 'admin_post_wp2ss_settings', array( __CLASS__, 'post_settings' ) );
	}

	/* ------------------------------------------------------------------ */

	public static function cap() {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	public static function url( $args = array() ) {
		$base = is_multisite() ? network_admin_url( 'settings.php?page=' . self::SLUG ) : admin_url( 'tools.php?page=' . self::SLUG );
		return add_query_arg( $args, $base );
	}

	private static function guard( $nonce_action ) {
		if ( ! current_user_can( self::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to do that.', 'wp2shell-scanner' ), 403 );
		}
		check_admin_referer( $nonce_action );
	}

	/** Checks permissions and starts buffering, so stray PHP warnings can't corrupt the JSON reply. */
	private static function ajax_guard() {
		ob_start();
		if ( ! current_user_can( self::cap() ) || ! check_ajax_referer( 'wp2ss', 'nonce', false ) ) {
			self::json( false, array( 'message' => __( 'Your session expired. Reload the page and try again.', 'wp2shell-scanner' ) ), 403 );
		}
	}

	private static function json( $ok, $data = null, $status = null ) {
		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}
		$ok ? wp_send_json_success( $data, $status ) : wp_send_json_error( $data, $status );
	}

	/** Per-request time budget: stay well inside the host's limit. */
	private static function budget() {
		$max = (int) ini_get( 'max_execution_time' );
		return $max > 0 ? max( 3, min( 10, $max / 3 ) ) : 10;
	}

	/* ------------------------------------------------------------------ */
	/* Menu & assets                                                       */
	/* ------------------------------------------------------------------ */

	public static function menu() {
		add_submenu_page(
			is_multisite() ? 'settings.php' : 'tools.php',
			__( 'PHP2Shell & wp2shell Scanner', 'wp2shell-scanner' ),
			__( 'PHP2Shell Scanner', 'wp2shell-scanner' ),
			self::cap(),
			self::SLUG,
			array( __CLASS__, 'page' )
		);
	}

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Scan', 'wp2shell-scanner' ) . '</a>' );
		return $links;
	}

	public static function assets( $hook ) {
		$on_page = false !== strpos( (string) $hook, self::SLUG );
		if ( ! $on_page && ! self::notice_wanted() ) {
			return;
		}
		wp_enqueue_style( 'wp2ss', WP2SS_URL . 'assets/admin.css', array(), WP2SS_VERSION );
		wp_enqueue_script( 'wp2ss', WP2SS_URL . 'assets/admin.js', array(), WP2SS_VERSION, true );
		wp_localize_script(
			'wp2ss',
			'WP2SS',
			array(
				'ajax'  => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( 'wp2ss' ),
				'i18n'  => array(
					'starting' => __( 'Starting scan…', 'wp2shell-scanner' ),
					'quick'    => __( 'Checking PHP, WordPress, plugins and users…', 'wp2shell-scanner' ),
					'files'    => __( 'Scanning files…', 'wp2shell-scanner' ),
					'core'     => __( 'Verifying WordPress core files…', 'wp2shell-scanner' ),
					'logs'     => __( 'Reading the server logs…', 'wp2shell-scanner' ),
					'done'     => __( 'Done. Loading results…', 'wp2shell-scanner' ),
					'error'    => __( 'The scan stopped:', 'wp2shell-scanner' ),
					'retry'    => __( 'Retrying…', 'wp2shell-scanner' ),
					'waiting'  => __( 'Waiting for another scan in progress…', 'wp2shell-scanner' ),
					'copied'   => __( 'Copied!', 'wp2shell-scanner' ),
				),
			)
		);
	}

	/* ------------------------------------------------------------------ */
	/* Page                                                                */
	/* ------------------------------------------------------------------ */

	public static function page() {
		if ( ! current_user_can( self::cap() ) ) {
			return;
		}
		$report   = WP2SS_Scanner::last_report();
		$job      = WP2SS_Scanner::current();
		$settings = WP2SS_Settings::get();
		$ignored  = WP2SS_Scanner::ignored();
		$verdict  = $report ? WP2SS_Scanner::verdict( $report['findings'], $ignored ) : '';
		$findings = $report ? $report['findings'] : array();
		$stale    = $report && time() - strtotime( $report['scanned'] ) > 30 * DAY_IN_SECONDS;
		?>
		<div class="wrap wp2ss">
			<h1><?php esc_html_e( 'PHP2Shell & wp2shell Scanner', 'wp2shell-scanner' ); ?></h1>
			<p class="wp2ss-lede">
				<?php esc_html_e( 'Checks whether this site is exposed to — or has been broken into through — PHP2Shell (CVE-2026-109618 / CVE-2026-109619, a bug in PHP itself) and wp2shell (CVE-2026-63030 / CVE-2026-60137, a bug in WordPress). The scan only reads; it never changes or deletes anything.', 'wp2shell-scanner' ); ?>
			</p>

			<?php if ( isset( $_GET['saved'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings saved.', 'wp2shell-scanner' ); ?></p></div>
			<?php endif; ?>

			<div class="wp2ss-grid">
				<section class="wp2ss-card wp2ss-status">
					<?php if ( $report ) : ?>
						<div class="wp2ss-verdict wp2ss-v-<?php echo esc_attr( strtolower( $verdict ) ); ?>">
							<span class="wp2ss-verdict-label"><?php echo esc_html( self::verdict_label( $verdict, $findings ) ); ?></span>
							<span class="wp2ss-verdict-sub"><?php echo esc_html( self::verdict_help( $verdict, $findings ) ); ?></span>
							<?php if ( 'VULNERABLE' === $verdict && self::has_vuln( $findings, 'version' ) && current_user_can( 'update_core' ) ) : ?>
								<a class="button button-secondary wp2ss-update" href="<?php echo esc_url( network_admin_url( 'update-core.php' ) ); ?>"><?php esc_html_e( 'Go to WordPress updates', 'wp2shell-scanner' ); ?></a>
							<?php endif; ?>
						</div>
						<p class="wp2ss-meta">
							<?php
							printf(
								/* translators: 1: time ago, 2: WordPress version, 3: PHP version, 4: PHP file count, 5: seconds */
								esc_html__( 'Last scan %1$s ago · WordPress %2$s · PHP %3$s · %4$s PHP files checked · %5$ss', 'wp2shell-scanner' ),
								esc_html( human_time_diff( strtotime( $report['scanned'] ) ) ),
								esc_html( $report['wp'] ),
								esc_html( isset( $report['php']['version'] ) ? $report['php']['version'] : PHP_VERSION ),
								esc_html( number_format_i18n( $report['stats']['php_files'] ) ),
								esc_html( number_format_i18n( $report['duration'] ) )
							);
							?>
						</p>
						<?php if ( $stale ) : ?>
							<p class="wp2ss-stale"><?php esc_html_e( 'This result is over a month old. Scan again to be sure it’s still accurate.', 'wp2shell-scanner' ); ?></p>
						<?php endif; ?>
					<?php else : ?>
						<div class="wp2ss-verdict wp2ss-v-none">
							<span class="wp2ss-verdict-label"><?php esc_html_e( 'Not scanned yet', 'wp2shell-scanner' ); ?></span>
							<span class="wp2ss-verdict-sub"><?php esc_html_e( 'Run your first scan — it usually takes under a minute.', 'wp2shell-scanner' ); ?></span>
						</div>
					<?php endif; ?>

					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="wp2ss-scan-form">
						<?php wp_nonce_field( 'wp2ss_scan' ); ?>
						<input type="hidden" name="action" value="wp2ss_scan">
						<button type="submit" class="button button-primary button-hero" id="wp2ss-scan" <?php echo $job ? 'data-running="1"' : ''; ?>>
							<?php $report ? esc_html_e( 'Scan again', 'wp2shell-scanner' ) : esc_html_e( 'Scan now', 'wp2shell-scanner' ); ?>
						</button>
						<?php if ( $report ) : ?>
							<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wp2ss_export' ), 'wp2ss_export' ) ); ?>"><?php esc_html_e( 'Download report (JSON)', 'wp2shell-scanner' ); ?></a>
						<?php endif; ?>
					</form>

					<div class="wp2ss-progress" id="wp2ss-progress" hidden>
						<div class="wp2ss-bar"><span style="width:0%"></span></div>
						<p class="wp2ss-progress-text" aria-live="polite"></p>
						<button type="button" class="button-link" id="wp2ss-cancel"><?php esc_html_e( 'Cancel', 'wp2shell-scanner' ); ?></button>
					</div>
				</section>

				<?php self::render_settings( $settings ); ?>
			</div>

			<?php
			if ( $report ) {
				if ( self::needs_host( $findings, $ignored ) ) {
					self::render_host_message( $report );
				}
				self::render_findings( $report, $ignored );
				if ( in_array( $verdict, array( 'COMPROMISED', 'SUSPICIOUS' ), true ) ) {
					self::render_cleanup();
				}
			}
			?>
		</div>
		<?php
	}

	private static function render_settings( $s ) {
		$schedules = array(
			'off'    => __( 'Off', 'wp2shell-scanner' ),
			'daily'  => __( 'Daily', 'wp2shell-scanner' ),
			'weekly' => __( 'Weekly', 'wp2shell-scanner' ),
		);
		$next      = wp_next_scheduled( WP2SS_Cron::HOOK );
		$env       = WP2SS_Env::get();
		?>
		<section class="wp2ss-card">
			<h2><?php esc_html_e( 'Settings', 'wp2shell-scanner' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wp2ss_settings' ); ?>
				<input type="hidden" name="action" value="wp2ss_settings">

				<p>
					<label for="wp2ss-schedule"><strong><?php esc_html_e( 'Automatic scans', 'wp2shell-scanner' ); ?></strong></label><br>
					<select id="wp2ss-schedule" name="schedule">
						<?php foreach ( $schedules as $k => $label ) : ?>
							<option value="<?php echo esc_attr( $k ); ?>" <?php selected( $s['schedule'], $k ); ?>><?php echo esc_html( $label ); ?></option>
						<?php endforeach; ?>
					</select>
					<?php if ( $next && 'off' !== $s['schedule'] ) : ?>
						<span class="description">
							<?php
							/* translators: %s: time until next scan */
							printf( esc_html__( 'Next in %s', 'wp2shell-scanner' ), esc_html( human_time_diff( $next ) ) );
							?>
						</span>
					<?php endif; ?>
				</p>

				<p>
					<label><input type="checkbox" name="email" value="1" <?php checked( $s['email'] ); ?>> <?php esc_html_e( 'Email me when an automatic scan finds something new', 'wp2shell-scanner' ); ?></label><br>
					<input type="email" name="email_to" class="regular-text" value="<?php echo esc_attr( $s['email_to'] ); ?>" placeholder="<?php echo esc_attr( get_site_option( 'admin_email' ) ); ?>" aria-label="<?php esc_attr_e( 'Alert email address', 'wp2shell-scanner' ); ?>">
				</p>

				<p>
					<label><input type="checkbox" name="core" value="1" <?php checked( $s['core'] ); ?>> <?php esc_html_e( 'Verify core files against wordpress.org', 'wp2shell-scanner' ); ?></label>
				</p>

				<details class="wp2ss-advanced" <?php echo ( $s['log'] || $s['error_log'] ) ? 'open' : ''; ?>>
					<summary><?php esc_html_e( 'Server logs (optional)', 'wp2shell-scanner' ); ?></summary>
					<p>
						<label for="wp2ss-errlog"><strong><?php esc_html_e( 'PHP error log', 'wp2shell-scanner' ); ?></strong></label><br>
						<input type="text" id="wp2ss-errlog" name="error_log" class="regular-text code" value="<?php echo esc_attr( $s['error_log'] ); ?>" placeholder="<?php echo esc_attr( $env['error_log'] ? $env['error_log'] : __( 'detected automatically', 'wp2shell-scanner' ) ); ?>">
						<br><span class="description"><?php esc_html_e( 'Where PHP2Shell attempts show up. Leave empty to use the log PHP reports, plus WordPress’s debug.log.', 'wp2shell-scanner' ); ?></span>
					</p>
					<p>
						<label for="wp2ss-log"><strong><?php esc_html_e( 'Web server access log', 'wp2shell-scanner' ); ?></strong></label><br>
						<input type="text" id="wp2ss-log" name="log" class="regular-text code" value="<?php echo esc_attr( $s['log'] ); ?>" placeholder="/var/log/nginx/access.log">
						<br><span class="description"><?php esc_html_e( 'If PHP can read it, scans also look for attack traffic. Ask your host if you’re not sure where it is. .gz files work.', 'wp2shell-scanner' ); ?></span>
					</p>
				</details>

				<?php submit_button( __( 'Save settings', 'wp2shell-scanner' ), 'secondary', 'submit', false ); ?>
			</form>

			<p class="wp2ss-env">
				<?php
				printf(
					/* translators: 1: PHP version, 2: server API, 3: operating system */
					esc_html__( 'Website PHP: %1$s (%2$s, %3$s)', 'wp2shell-scanner' ),
					esc_html( $env['version'] ),
					esc_html( self::sapi_label( $env['sapi'] ) ),
					esc_html( $env['os'] )
				);
				?>
			</p>
		</section>
		<?php
	}

	public static function sapi_label( $sapi ) {
		$l = array(
			'apache2handler' => 'Apache mod_php',
			'fpm-fcgi'       => 'PHP-FPM',
			'cgi-fcgi'       => 'FastCGI',
			'litespeed'      => 'LiteSpeed',
			'frankenphp'     => 'FrankenPHP',
			'cli'            => 'command line',
		);
		return isset( $l[ $sapi ] ) ? $l[ $sapi ] : $sapi;
	}

	/** Does a PHP finding need the host's help (vulnerable or unconfirmed)? */
	private static function needs_host( $findings, $ignored ) {
		foreach ( $findings as $f ) {
			if ( 'php' === $f['type'] && WP2SS_Scanner::sev_rank( $f['severity'] ) >= 3 && ! WP2SS_Scanner::is_ignored( $f, $ignored ) ) {
				return true;
			}
		}
		return false;
	}

	/** A ready-to-send support message, because most site owners can't update PHP themselves. */
	private static function render_host_message( $report ) {
		$env   = WP2SS_Env::get();
		$sig   = WP2SS_Scanner::signatures();
		$fixed = isset( $sig['php_fixed'][ $env['branch'] ] ) ? $sig['php_fixed'][ $env['branch'] ] : '8.2.35 or newer';
		$msg   = sprintf(
			/* translators: 1: site URL, 2: PHP version, 3: server API, 4: fixed version */
			__( "Hello,\n\nMy website %1\$s runs PHP %2\$s (%3\$s). A security scan says this version may be affected by PHP2Shell (CVE-2026-109618 and CVE-2026-109619), the critical PHP vulnerabilities announced on October 21, 2026.\n\nCould you please:\n1. Update PHP for my site to %4\$s (or your patched package), or confirm that the fix for both CVEs has already been applied to this server, and\n2. Restart PHP afterwards, and\n3. Until then, consider setting session.upload_progress.enabled = 0 in php.ini as a temporary protection.\n\nCould you also let me know whether you've seen any signs of these attacks against my site since October 17, 2026?\n\nThank you!", 'wp2shell-scanner' ),
			$report['site'],
			$env['version'],
			self::sapi_label( $env['sapi'] ),
			$fixed
		);
		?>
		<section class="wp2ss-card wp2ss-host">
			<h2><?php esc_html_e( 'Your host needs to update PHP', 'wp2shell-scanner' ); ?></h2>
			<p><?php esc_html_e( 'PHP2Shell is fixed by updating PHP on the server, which on most hosting plans only your host can do. Copy this message into a support ticket or live chat:', 'wp2shell-scanner' ); ?></p>
			<textarea id="wp2ss-host-msg" class="large-text" rows="10" readonly><?php echo esc_textarea( $msg ); ?></textarea>
			<p>
				<button type="button" class="button button-primary" id="wp2ss-copy"><?php esc_html_e( 'Copy message', 'wp2shell-scanner' ); ?></button>
				<span class="description"><?php esc_html_e( 'Some hosts let you pick a newer PHP version yourself (look for “PHP version” or “MultiPHP” in your hosting control panel). Choose 8.2 or newer.', 'wp2shell-scanner' ); ?></span>
			</p>
		</section>
		<?php
	}

	private static function render_findings( $report, $ignored ) {
		$active = array();
		$muted  = array();
		foreach ( $report['findings'] as $f ) {
			if ( WP2SS_Scanner::is_ignored( $f, $ignored ) ) {
				$muted[] = $f;
			} else {
				$active[] = $f;
			}
		}
		$counts = array_count_values( wp_list_pluck( $active, 'severity' ) );
		?>
		<h2 class="wp2ss-h2"><?php esc_html_e( 'Findings', 'wp2shell-scanner' ); ?>
			<?php foreach ( array( 'critical', 'high', 'medium', 'low' ) as $sev ) : ?>
				<?php if ( ! empty( $counts[ $sev ] ) ) : ?>
					<span class="wp2ss-pill wp2ss-s-<?php echo esc_attr( $sev ); ?>"><?php echo esc_html( $counts[ $sev ] . ' ' . self::sev_label( $sev ) ); ?></span>
				<?php endif; ?>
			<?php endforeach; ?>
		</h2>

		<?php self::findings_table( $active, false ); ?>

		<?php if ( $muted ) : ?>
			<details class="wp2ss-ignored">
				<summary>
					<?php
					/* translators: %d: number of ignored findings */
					printf( esc_html( _n( '%d ignored finding', '%d ignored findings', count( $muted ), 'wp2shell-scanner' ) ), count( $muted ) );
					?>
				</summary>
				<?php self::findings_table( $muted, true ); ?>
			</details>
		<?php endif; ?>
		<?php
	}

	private static function findings_table( $rows, $muted ) {
		if ( ! $rows ) {
			echo '<p class="wp2ss-empty">' . esc_html__( 'Nothing to show.', 'wp2shell-scanner' ) . '</p>';
			return;
		}
		?>
		<table class="widefat wp2ss-table">
			<thead><tr>
				<th class="wp2ss-col-sev"><?php esc_html_e( 'Severity', 'wp2shell-scanner' ); ?></th>
				<th><?php esc_html_e( 'Finding', 'wp2shell-scanner' ); ?></th>
				<th><?php esc_html_e( 'What to do', 'wp2shell-scanner' ); ?></th>
				<th class="wp2ss-col-act"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'wp2shell-scanner' ); ?></span></th>
			</tr></thead>
			<tbody>
			<?php foreach ( $rows as $f ) : ?>
				<?php $loc = (string) $f['location']; ?>
				<tr data-id="<?php echo esc_attr( $f['id'] ); ?>">
					<td class="wp2ss-col-sev"><span class="wp2ss-pill wp2ss-s-<?php echo esc_attr( $f['severity'] ); ?>"><?php echo esc_html( self::sev_label( $f['severity'] ) ); ?></span></td>
					<td>
						<?php echo esc_html( $f['message'] ); ?>
						<?php if ( 0 === strpos( $loc, 'user:' ) && get_edit_user_link( (int) substr( $loc, 5 ) ) ) : ?>
							<a class="wp2ss-loc" href="<?php echo esc_url( get_edit_user_link( (int) substr( $loc, 5 ) ) ); ?>"><?php esc_html_e( 'View user', 'wp2shell-scanner' ); ?></a>
						<?php elseif ( $loc && ! preg_match( '/^(user|rest|role):/', $loc ) ) : ?>
							<code class="wp2ss-loc"><?php echo esc_html( $loc ); ?></code>
						<?php endif; ?>
					</td>
					<td class="wp2ss-advice"><?php echo esc_html( $f['advice'] ); ?></td>
					<td class="wp2ss-col-act">
						<?php if ( 'info' !== $f['severity'] ) : ?>
							<button type="button" class="button-link wp2ss-toggle" data-id="<?php echo esc_attr( $f['id'] ); ?>" data-ignore="<?php echo $muted ? '0' : '1'; ?>">
								<?php $muted ? esc_html_e( 'Restore', 'wp2shell-scanner' ) : esc_html_e( 'Ignore', 'wp2shell-scanner' ); ?>
							</button>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	private static function render_cleanup() {
		?>
		<section class="wp2ss-card wp2ss-cleanup">
			<h2><?php esc_html_e( 'If this site has been compromised', 'wp2shell-scanner' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Take a full backup of files and database first. It’s your evidence, and lets you undo mistakes.', 'wp2shell-scanner' ); ?></li>
				<li><?php esc_html_e( 'Close the way in: update WordPress (6.8.6, 6.9.5, 7.0.2 or later) and have your host update PHP (8.2.35, 8.3.36, 8.4.27, 8.5.12 or later).', 'wp2shell-scanner' ); ?></li>
				<li><?php esc_html_e( 'Remove the flagged files, plugins and administrator accounts.', 'wp2shell-scanner' ); ?></li>
				<li><?php esc_html_e( 'Change every secret: all administrator passwords, the database password, API keys stored in plugins, and the security keys (salts) in wp-config.php. PHP2Shell can leak these from memory.', 'wp2shell-scanner' ); ?></li>
				<li><?php esc_html_e( 'Check for other ways back in: must-use plugins, .htaccess and .user.ini files, scheduled tasks and server cron jobs. Then scan again.', 'wp2shell-scanner' ); ?></li>
			</ol>
			<p class="description"><?php esc_html_e( 'If you’re not comfortable doing this, ask your host or a WordPress security service — many will clean a site for a fee. The JSON report lists everything found.', 'wp2shell-scanner' ); ?></p>
		</section>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Labels                                                              */
	/* ------------------------------------------------------------------ */

	public static function sev_label( $s ) {
		$l = array(
			'critical' => __( 'Critical', 'wp2shell-scanner' ),
			'high'     => __( 'High', 'wp2shell-scanner' ),
			'medium'   => __( 'Medium', 'wp2shell-scanner' ),
			'low'      => __( 'Low', 'wp2shell-scanner' ),
			'info'     => __( 'Info', 'wp2shell-scanner' ),
		);
		return isset( $l[ $s ] ) ? $l[ $s ] : $s;
	}

	/** Is there a (non-ignored, high+) weakness of this type: 'php' or 'version' (WordPress)? */
	public static function has_vuln( $findings, $type ) {
		foreach ( (array) $findings as $f ) {
			if ( $type === $f['type'] && WP2SS_Scanner::sev_rank( $f['severity'] ) >= 4 && ! WP2SS_Scanner::is_ignored( $f ) ) {
				return true;
			}
		}
		return false;
	}

	public static function verdict_label( $v, $findings = array() ) {
		if ( 'VULNERABLE' === $v ) {
			$php = self::has_vuln( $findings, 'php' );
			$wp  = self::has_vuln( $findings, 'version' );
			if ( $php && $wp ) {
				return __( 'Vulnerable — update PHP and WordPress', 'wp2shell-scanner' );
			}
			if ( $php ) {
				return __( 'Vulnerable — PHP needs updating', 'wp2shell-scanner' );
			}
			return __( 'Vulnerable — update WordPress', 'wp2shell-scanner' );
		}
		$l = array(
			'COMPROMISED' => __( 'Compromised', 'wp2shell-scanner' ),
			'SUSPICIOUS'  => __( 'Suspicious', 'wp2shell-scanner' ),
			'REVIEW'      => __( 'Needs review', 'wp2shell-scanner' ),
			'CLEAN'       => __( 'No signs of PHP2Shell or wp2shell', 'wp2shell-scanner' ),
		);
		return isset( $l[ $v ] ) ? $l[ $v ] : $v;
	}

	public static function verdict_help( $v, $findings = array() ) {
		if ( 'VULNERABLE' === $v ) {
			return self::has_vuln( $findings, 'php' )
				? __( 'No signs of a break-in, but this server’s PHP can be attacked through PHP2Shell. Ask your host to update it — there’s a message ready to send below.', 'wp2shell-scanner' )
				: __( 'No signs of a break-in, but this WordPress version can be attacked through wp2shell. Update it now.', 'wp2shell-scanner' );
		}
		$l = array(
			'COMPROMISED' => __( 'Strong evidence of an attack. Follow the steps at the bottom of this page.', 'wp2shell-scanner' ),
			'SUSPICIOUS'  => __( 'Something here needs a closer look today.', 'wp2shell-scanner' ),
			'REVIEW'      => __( 'A few things to confirm, nothing alarming on its own.', 'wp2shell-scanner' ),
			'CLEAN'       => __( 'No known indicators found. Keep PHP and WordPress updated.', 'wp2shell-scanner' ),
		);
		return isset( $l[ $v ] ) ? $l[ $v ] : '';
	}

	/* ------------------------------------------------------------------ */
	/* Notice                                                              */
	/* ------------------------------------------------------------------ */

	private static function notice_verdict() {
		$r = WP2SS_Scanner::last_report();
		if ( ! $r ) {
			return array( null, '' );
		}
		return array( $r, WP2SS_Scanner::verdict( $r['findings'] ) );
	}

	private static function notice_wanted() {
		if ( ! current_user_can( self::cap() ) ) {
			return false;
		}
		list( $r, $v ) = self::notice_verdict();
		return $r && in_array( $v, array( 'COMPROMISED', 'SUSPICIOUS', 'VULNERABLE' ), true )
			&& get_user_meta( get_current_user_id(), 'wp2ss_dismissed', true ) !== $r['id'];
	}

	public static function notice() {
		$screen = get_current_screen();
		if ( ( $screen && false !== strpos( $screen->id, self::SLUG ) ) || ! self::notice_wanted() ) {
			return;
		}
		list( $r, $v ) = self::notice_verdict();
		?>
		<div class="notice notice-error is-dismissible wp2ss-notice" data-report="<?php echo esc_attr( $r['id'] ); ?>">
			<p>
				<strong><?php echo esc_html( sprintf( /* translators: %s: verdict */ __( 'PHP2Shell Scanner: %s', 'wp2shell-scanner' ), self::verdict_label( $v, $r['findings'] ) ) ); ?></strong> —
				<?php echo esc_html( self::verdict_help( $v, $r['findings'] ) ); ?>
				<a href="<?php echo esc_url( self::url() ); ?>"><?php esc_html_e( 'See findings', 'wp2shell-scanner' ); ?></a>
			</p>
		</div>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* AJAX                                                                */
	/* ------------------------------------------------------------------ */

	public static function ajax_start() {
		self::ajax_guard();
		$state = WP2SS_Scanner::start( WP2SS_Settings::scan_args(), 'manual', ! empty( $_POST['force'] ) ); // phpcs:ignore WordPress.Security.NonceVerification
		self::json( true, self::state_payload( $state ) );
	}

	public static function ajax_step() {
		self::ajax_guard();
		$r = WP2SS_Scanner::step( self::budget() );
		if ( null === $r ) {
			$report = WP2SS_Scanner::last_report();
			self::json( true, array( 'done' => true, 'verdict' => $report ? $report['verdict'] : '' ) );
		}
		self::json( true, self::state_payload( $r ) );
	}

	public static function ajax_cancel() {
		self::ajax_guard();
		WP2SS_Scanner::cancel();
		self::json( true );
	}

	public static function ajax_ignore() {
		self::ajax_guard();
		$id     = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		$ignore = ! empty( $_POST['ignore'] ); // phpcs:ignore WordPress.Security.NonceVerification
		if ( ! WP2SS_Scanner::set_ignored( $id, $ignore, get_current_user_id() ) ) {
			self::json( false );
		}
		self::json( true );
	}

	public static function ajax_dismiss() {
		self::ajax_guard();
		$id = isset( $_POST['report'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', wp_unslash( $_POST['report'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification,WordPress.Security.ValidatedSanitizedInput
		update_user_meta( get_current_user_id(), 'wp2ss_dismissed', $id );
		self::json( true );
	}

	private static function state_payload( $s ) {
		if ( ! empty( $s['verdict'] ) ) {
			return array( 'done' => true, 'verdict' => $s['verdict'] );
		}
		return array(
			'done'     => false,
			'busy'     => ! empty( $s['busy'] ),
			'phase'    => $s['phase'],
			'progress' => (int) $s['progress'],
			'files'    => (int) $s['stats']['php_files'],
		);
	}

	/* ------------------------------------------------------------------ */
	/* Form posts                                                          */
	/* ------------------------------------------------------------------ */

	/** No-JavaScript fallback: run the whole scan in this request. */
	public static function post_scan() {
		self::guard( 'wp2ss_scan' );
		WP2SS_Scanner::run_all( WP2SS_Settings::scan_args(), 'manual' );
		wp_safe_redirect( self::url() );
		exit;
	}

	public static function post_export() {
		self::guard( 'wp2ss_export' );
		$report = WP2SS_Scanner::last_report();
		if ( $report ) {
			$report['ignored'] = array();
			foreach ( $report['findings'] as $f ) {
				if ( WP2SS_Scanner::is_ignored( $f ) ) {
					$report['ignored'][] = $f['id'];
				}
			}
		}
		$host = sanitize_file_name( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="php2shell-scan-' . $host . '-' . gmdate( 'Ymd-His' ) . '.json"' );
		echo wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR );
		exit;
	}

	public static function post_settings() {
		self::guard( 'wp2ss_settings' );
		// phpcs:disable WordPress.Security.NonceVerification
		WP2SS_Settings::save(
			array(
				'schedule'  => isset( $_POST['schedule'] ) ? sanitize_key( wp_unslash( $_POST['schedule'] ) ) : 'weekly',
				'email'     => ! empty( $_POST['email'] ),
				'email_to'  => isset( $_POST['email_to'] ) ? sanitize_email( wp_unslash( $_POST['email_to'] ) ) : '',
				'core'      => ! empty( $_POST['core'] ),
				'log'       => isset( $_POST['log'] ) ? sanitize_text_field( wp_unslash( $_POST['log'] ) ) : '',
				'error_log' => isset( $_POST['error_log'] ) ? sanitize_text_field( wp_unslash( $_POST['error_log'] ) ) : '',
			)
		);
		// phpcs:enable
		wp_safe_redirect( self::url( array( 'saved' => 1 ) ) );
		exit;
	}
}
