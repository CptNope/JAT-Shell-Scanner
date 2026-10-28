<?php
/**
 * Admin screen: verdict, next steps, findings, quarantine, fleet and settings.
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
		add_filter( 'plugin_row_meta', array( __CLASS__, 'row_meta' ), 10, 2 );

		foreach ( array( 'start', 'step', 'cancel', 'ignore', 'dismiss', 'fix', 'undo', 'purge' ) as $a ) {
			add_action( 'wp_ajax_wp2ss_' . $a, array( __CLASS__, 'ajax_' . $a ) );
		}
		foreach ( array( 'scan', 'export', 'settings', 'fix_all', 'fleet', 'fleet_send', 'fleet_forget', 'fleet_rotate', 'fleet_csv', 'fleet_alerts', 'fleet_test', 'fleet_rescan', 'fleet_clear' ) as $a ) {
			add_action( 'admin_post_wp2ss_' . $a, array( __CLASS__, 'post_' . $a ) );
		}
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
			wp_die( esc_html__( 'You are not allowed to do that.', 'jat-shell-scanner' ), 403 );
		}
		check_admin_referer( $nonce_action );
	}

	/** Checks permissions and starts buffering, so stray PHP warnings can't corrupt the JSON reply. */
	private static function ajax_guard() {
		ob_start();
		if ( ! current_user_can( self::cap() ) || ! check_ajax_referer( 'wp2ss', 'nonce', false ) ) {
			self::json( false, array( 'message' => __( 'Your session expired. Reload the page and try again.', 'jat-shell-scanner' ) ), 403 );
		}
	}

	private static function json( $ok, $data = null, $status = null ) {
		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}
		$ok ? wp_send_json_success( $data, $status ) : wp_send_json_error( $data, $status );
	}

	private static function budget() {
		$max = (int) ini_get( 'max_execution_time' );
		return $max > 0 ? max( 3, min( 10, $max / 3 ) ) : 10;
	}

	private static function back( $tab, $args = array(), $to_tabs = true ) {
		// Error text never travels in the URL (a crafted link could show any message): it waits for this user.
		if ( isset( $args['err'] ) ) {
			set_transient( 'wp2ss_err_' . get_current_user_id(), (string) $args['err'], 5 * MINUTE_IN_SECONDS );
			$args['err'] = 1;
		}
		// Land on the tabs (where the message is shown), not on the hero above them.
		wp_safe_redirect( self::url( array_merge( array( 'tab' => $tab ), $args ) ) . ( $to_tabs ? '#wp2ss-tabs' : '' ) );
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* Menu & assets                                                       */
	/* ------------------------------------------------------------------ */

	public static function menu() {
		add_submenu_page(
			is_multisite() ? 'settings.php' : 'tools.php',
			__( 'PHP2Shell & wp2shell Scanner', 'jat-shell-scanner' ),
			__( 'PHP2Shell Scanner', 'jat-shell-scanner' ),
			self::cap(),
			self::SLUG,
			array( __CLASS__, 'page' )
		);
	}

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Scan', 'jat-shell-scanner' ) . '</a>' );
		return $links;
	}

	/** Where people get help: the forum on WordPress.org, issues on GitHub. */
	public static function support_url() {
		return 'wporg' === WP2SS_CHANNEL
			? 'https://wordpress.org/support/plugin/' . WP2SS_WPORG_SLUG . '/'
			: 'https://github.com/' . WP2SS_REPO . '/issues';
	}

	/** Links under the plugin's description on the Plugins screen. */
	public static function row_meta( $links, $file ) {
		if ( WP2SS_BASENAME !== $file ) {
			return $links;
		}
		$extra = array(
			WP2SS_DOCS_URL                    => __( 'Documentation', 'jat-shell-scanner' ),
			self::support_url()                                   => __( 'Support', 'jat-shell-scanner' ),
			WP2SS_AUTHOR_URL . 'book-a-call/'                     => __( 'Hire the author', 'jat-shell-scanner' ),
		);
		foreach ( $extra as $url => $label ) {
			$links[] = '<a href="' . esc_url( $url ) . '" target="_blank" rel="noopener">' . esc_html( $label ) . '</a>';
		}
		return $links;
	}

	/** A short "about" footer, shown only on the scanner's own page. */
	private static function render_about() {
		?>
		<aside class="wp2ss-about" aria-label="<?php esc_attr_e( 'About this plugin', 'jat-shell-scanner' ); ?>">
			<p>
				<strong><?php esc_html_e( 'Free and open source, by Jeremy Anderson.', 'jat-shell-scanner' ); ?></strong>
				<?php esc_html_e( 'Need hands-on help with a vulnerable or hacked WordPress site, or a site built to stay secure? I build and look after WordPress sites.', 'jat-shell-scanner' ); ?>
			</p>
			<p class="wp2ss-about-links">
				<a class="button" href="<?php echo esc_url( WP2SS_AUTHOR_URL . 'book-a-call/' ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Book a call', 'jat-shell-scanner' ); ?></a>
				<a href="<?php echo esc_url( WP2SS_AUTHOR_URL . 'services/' ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Services', 'jat-shell-scanner' ); ?></a>
				<a href="<?php echo esc_url( WP2SS_DOCS_URL ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Documentation', 'jat-shell-scanner' ); ?></a>
				<a href="<?php echo esc_url( self::support_url() ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Report a problem', 'jat-shell-scanner' ); ?></a>
			</p>
		</aside>
		<?php
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
					'starting' => __( 'Starting scan…', 'jat-shell-scanner' ),
					'quick'    => __( 'Checking PHP, WordPress, plugins, users and the database…', 'jat-shell-scanner' ),
					'files'    => __( 'Scanning files…', 'jat-shell-scanner' ),
					'core'     => __( 'Verifying WordPress core files…', 'jat-shell-scanner' ),
					'plugins'  => __( 'Verifying plugin files…', 'jat-shell-scanner' ),
					'logs'     => __( 'Reading the server logs…', 'jat-shell-scanner' ),
					'done'     => __( 'Done. Loading results…', 'jat-shell-scanner' ),
					'error'    => __( 'The scan stopped:', 'jat-shell-scanner' ),
					'retry'    => __( 'Retrying…', 'jat-shell-scanner' ),
					'waiting'  => __( 'Waiting for another scan in progress…', 'jat-shell-scanner' ),
					'copied'   => __( 'Copied', 'jat-shell-scanner' ),
					'working'  => __( 'Working…', 'jat-shell-scanner' ),
					'purge'    => __( 'Delete this for good? This can’t be undone.', 'jat-shell-scanner' ),
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
		$report  = WP2SS_Scanner::last_report();
		$job     = WP2SS_Scanner::current();
		$ignored = WP2SS_Scanner::ignored();
		$tabs    = array(
			'findings'   => __( 'Findings', 'jat-shell-scanner' ),
			'quarantine' => __( 'Quarantine', 'jat-shell-scanner' ),
			'fleet'      => __( 'Fleet', 'jat-shell-scanner' ),
			'settings'   => __( 'Settings', 'jat-shell-scanner' ),
		);
		$tab     = isset( $_GET['tab'] ) && isset( $tabs[ $_GET['tab'] ] ) ? sanitize_key( $_GET['tab'] ) : 'findings'; // phpcs:ignore WordPress.Security.NonceVerification
		$q_count = count( WP2SS_Fixes::records() );
		if ( $q_count ) {
			/* translators: %d: number of quarantined items or undoable fixes */
			$tabs['quarantine'] = sprintf( __( 'Quarantine (%d)', 'jat-shell-scanner' ), $q_count );
		}
		?>
		<div class="wrap wp2ss">
			<h1 class="wp2ss-title"><?php esc_html_e( 'PHP2Shell & wp2shell Scanner', 'jat-shell-scanner' ); ?></h1>
			<?php self::render_hero( $report, $job, $ignored ); ?>

			<?php
			if ( $report ) {
				self::render_next_steps( $report, $ignored );
			}
			?>

			<nav id="wp2ss-tabs" class="nav-tab-wrapper wp2ss-tabs" aria-label="<?php esc_attr_e( 'Scanner sections', 'jat-shell-scanner' ); ?>">
				<?php foreach ( $tabs as $k => $label ) : ?>
					<a href="<?php echo esc_url( self::url( array( 'tab' => $k ) ) . '#wp2ss-tabs' ); ?>" class="nav-tab <?php echo $tab === $k ? 'nav-tab-active' : ''; ?>" <?php echo $tab === $k ? 'aria-current="page"' : ''; ?>><?php echo esc_html( $label ); ?></a>
				<?php endforeach; ?>
			</nav>

			<div class="wp2ss-panel">
				<?php
				self::flash();
				switch ( $tab ) {
					case 'quarantine':
						self::render_quarantine();
						break;
					case 'fleet':
						self::render_fleet();
						break;
					case 'settings':
						self::render_settings();
						break;
					default:
						if ( $report ) {
							self::render_findings( $report, $ignored );
						} else {
							echo '<p class="wp2ss-empty">' . esc_html__( 'Run your first scan to see findings here.', 'jat-shell-scanner' ) . '</p>';
						}
				}
				?>
			</div>
			<?php self::render_about(); ?>
		</div>
		<?php
	}

	/** Messages after a form post (?done=…). */
	private static function flash() {
		// phpcs:disable WordPress.Security.NonceVerification
		$map = array(
			'saved'      => array( 'success', __( 'Settings saved.', 'jat-shell-scanner' ) ),
			'fixed'      => array( 'success', __( 'Done. Everything that was moved is in the Quarantine tab, where you can undo it.', 'jat-shell-scanner' ) ),
			'fleet'      => array( 'success', __( 'Fleet settings saved.', 'jat-shell-scanner' ) ),
			'sent'       => array( 'success', __( 'Report sent to the hub.', 'jat-shell-scanner' ) ),
			'rotated'    => array( 'warning', __( 'New fleet key created. Member sites must be given the new key before they can report again.', 'jat-shell-scanner' ) ),
			'forgot'     => array( 'success', __( 'Site removed from the fleet list.', 'jat-shell-scanner' ) ),
			'alerts'     => array( 'success', __( 'Alert settings saved.', 'jat-shell-scanner' ) ),
			'tested'     => array( 'success', __( 'Test alert sent. Check your inbox or chat channel.', 'jat-shell-scanner' ) ),
			'cleared'    => array( 'success', __( 'The list is empty. Sites reappear (and register again) with their next report.', 'jat-shell-scanner' ) ),
			'rescan'     => array( 'success', __( 'Scan requested. Sites pick this up within an hour (sites on version 1.2 or older can’t; scan those yourself).', 'jat-shell-scanner' ) ),
		);
		$done = isset( $_GET['done'] ) ? sanitize_key( $_GET['done'] ) : '';
		$err = '';
		if ( ! empty( $_GET['err'] ) ) {
			$err = (string) get_transient( 'wp2ss_err_' . get_current_user_id() );
			delete_transient( 'wp2ss_err_' . get_current_user_id() );
		}
		// phpcs:enable
		if ( isset( $map[ $done ] ) ) {
			printf( '<div class="notice notice-%s inline is-dismissible wp2ss-flash"><p>%s</p></div>', esc_attr( $map[ $done ][0] ), esc_html( $map[ $done ][1] ) );
		}
		if ( $err ) {
			printf( '<div class="notice notice-error inline is-dismissible wp2ss-flash"><p>%s</p></div>', esc_html( $err ) );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Hero: the verdict sentence and the two doors                        */
	/* ------------------------------------------------------------------ */

	/** State of each "door" and the "doorstep", from the findings. */
	public static function doors( $findings, $ignored ) {
		$php = array( 'state' => 'unknown', 'f' => null );
		$wp  = array( 'state' => 'shut', 'f' => null );
		$in  = array( 'state' => 'clear', 'critical' => 0, 'high' => 0, 'medium' => 0 );
		foreach ( (array) $findings as $f ) {
			$ign  = WP2SS_Scanner::is_ignored( $f, $ignored );
			$rank = WP2SS_Scanner::sev_rank( $f['severity'] );
			if ( 'php' === $f['type'] && preg_match( '/PHP2Shell fix|vulnerable to PHP2Shell|no official PHP2Shell fix|never get a PHP2Shell fix|older than the PHP2Shell fix/', $f['message'] ) ) {
				if ( $ign || 1 === $rank ) {
					$php = array( 'state' => 'shut', 'f' => $f );
				} elseif ( 3 === $rank ) {
					$php = array( 'state' => 'ask', 'f' => $f );
				} else {
					$php = array( 'state' => 'open', 'f' => $f );
				}
			} elseif ( 'version' === $f['type'] ) {
				$wp = array( 'state' => ( $rank >= 4 && ! $ign ) ? 'open' : 'shut', 'f' => $f );
			} elseif ( ! in_array( $f['type'], WP2SS_Scanner::VULN_TYPES, true ) && ! $ign && isset( $in[ $f['severity'] ] ) ) {
				$in[ $f['severity'] ]++;
			}
		}
		if ( $in['critical'] ) {
			$in['state'] = 'breach';
		} elseif ( $in['high'] ) {
			$in['state'] = 'suspect';
		} elseif ( $in['medium'] ) {
			$in['state'] = 'check';
		}
		return array( $php, $wp, $in );
	}

	/** The one sentence that sums the scan up. */
	private static function sentence( $verdict, $php, $wp, $in ) {
		$doors_open = ( 'open' === $php['state'] ) + ( 'open' === $wp['state'] );
		if ( 'breach' === $in['state'] ) {
			return __( 'Someone has very likely broken in.', 'jat-shell-scanner' );
		}
		if ( 'suspect' === $in['state'] ) {
			return __( 'Something here looks like a break-in. Check it today.', 'jat-shell-scanner' );
		}
		if ( 2 === $doors_open ) {
			return __( 'Both PHP and WordPress are open to attack. No signs anyone got in.', 'jat-shell-scanner' );
		}
		if ( 'open' === $php['state'] ) {
			return __( 'PHP is open to attack. No signs anyone got in.', 'jat-shell-scanner' );
		}
		if ( 'open' === $wp['state'] ) {
			return __( 'WordPress is open to attack. No signs anyone got in.', 'jat-shell-scanner' );
		}
		if ( 'ask' === $php['state'] ) {
			return __( 'Probably safe — your host needs to confirm PHP is patched.', 'jat-shell-scanner' );
		}
		if ( 'check' === $in['state'] ) {
			return __( 'No break-in found. A few things are worth a look.', 'jat-shell-scanner' );
		}
		return __( 'Both doors are shut and nobody got in.', 'jat-shell-scanner' );
	}

	private static function render_hero( $report, $job, $ignored ) {
		$state = 'none';
		if ( $report ) {
			$verdict          = WP2SS_Scanner::verdict( $report['findings'], $ignored );
			list( $php, $wp, $in ) = self::doors( $report['findings'], $ignored );
			$state            = strtolower( $verdict );
		}
		$env = WP2SS_Env::get();
		?>
		<section class="wp2ss-hero wp2ss-v-<?php echo esc_attr( $state ); ?>" aria-labelledby="wp2ss-verdict">
			<div class="wp2ss-hero-head">
				<div>
					<?php if ( $report ) : ?>
						<h2 id="wp2ss-verdict" class="wp2ss-sentence"><?php echo esc_html( self::sentence( $verdict, $php, $wp, $in ) ); ?></h2>
						<p class="wp2ss-meta">
							<?php
							printf(
								/* translators: 1: time ago, 2: number of PHP files, 3: duration in seconds */
								esc_html__( 'Scanned %1$s ago — %2$s PHP files in %3$ss.', 'jat-shell-scanner' ),
								esc_html( human_time_diff( strtotime( $report['scanned'] ) ) ),
								esc_html( number_format_i18n( $report['stats']['php_files'] ) ),
								esc_html( number_format_i18n( $report['duration'] ) )
							);
							if ( time() - strtotime( $report['scanned'] ) > 30 * DAY_IN_SECONDS ) {
								echo ' <strong>' . esc_html__( 'That’s over a month ago — scan again.', 'jat-shell-scanner' ) . '</strong>';
							}
							?>
						</p>
					<?php else : ?>
						<h2 id="wp2ss-verdict" class="wp2ss-sentence"><?php esc_html_e( 'Is the door open, and did anyone come in?', 'jat-shell-scanner' ); ?></h2>
						<p class="wp2ss-meta"><?php esc_html_e( 'This checks whether PHP2Shell (a bug in PHP) or wp2shell (a bug in WordPress) can be used against this site, and looks for signs someone already did. It only reads — it changes nothing unless you click a fix.', 'jat-shell-scanner' ); ?></p>
					<?php endif; ?>
				</div>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="wp2ss-scan-form" class="wp2ss-hero-actions">
					<?php wp_nonce_field( 'wp2ss_scan' ); ?>
					<input type="hidden" name="action" value="wp2ss_scan">
					<button type="submit" class="button button-primary button-hero" id="wp2ss-scan" <?php echo $job ? 'data-running="1"' : ''; ?>>
						<?php $report ? esc_html_e( 'Scan again', 'jat-shell-scanner' ) : esc_html_e( 'Scan now', 'jat-shell-scanner' ); ?>
					</button>
					<?php if ( $report ) : ?>
						<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wp2ss_export' ), 'wp2ss_export' ) ); ?>"><?php esc_html_e( 'Download report', 'jat-shell-scanner' ); ?></a>
					<?php endif; ?>
				</form>
			</div>

			<div class="wp2ss-progress" id="wp2ss-progress" hidden>
				<div class="wp2ss-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><span></span></div>
				<p class="wp2ss-progress-text" aria-live="polite"></p>
				<button type="button" class="button-link" id="wp2ss-cancel"><?php esc_html_e( 'Cancel scan', 'jat-shell-scanner' ); ?></button>
			</div>

			<?php if ( $report ) : ?>
				<div class="wp2ss-doors">
					<?php
					$sig   = WP2SS_Scanner::signatures();
					$fixed = isset( $sig['php_fixed'][ $env['branch'] ] ) ? $sig['php_fixed'][ $env['branch'] ] : '8.2.35+';
					self::door(
						'PHP ' . ( isset( $report['php']['version'] ) ? $report['php']['version'] : $env['version'] ),
						__( 'PHP2Shell', 'jat-shell-scanner' ),
						$php['state'],
						array(
							'shut'    => __( 'Patched', 'jat-shell-scanner' ),
							'open'    => __( 'Open to attack', 'jat-shell-scanner' ),
							'ask'     => __( 'Ask your host', 'jat-shell-scanner' ),
							'unknown' => __( 'Not checked', 'jat-shell-scanner' ),
						),
						array(
							'shut'    => __( 'This PHP has the fix.', 'jat-shell-scanner' ),
							/* translators: %s: fixed PHP version */
							'open'    => sprintf( __( 'Needs updating to %s or later. Only your host can usually do this.', 'jat-shell-scanner' ), $fixed ),
							'ask'     => __( 'An operating-system build: it may already carry the fix without a new version number.', 'jat-shell-scanner' ),
							'unknown' => '',
						)
					);
					self::door(
						'WordPress ' . $report['wp'],
						__( 'wp2shell', 'jat-shell-scanner' ),
						$wp['state'],
						array(
							'shut' => __( 'Patched', 'jat-shell-scanner' ),
							'open' => __( 'Open to attack', 'jat-shell-scanner' ),
						),
						array(
							'shut' => __( 'This version isn’t affected.', 'jat-shell-scanner' ),
							'open' => __( 'Update to 6.8.6, 6.9.5, 7.0.2 or newer.', 'jat-shell-scanner' ),
						)
					);
					$tally = array();
					foreach ( array( 'critical', 'high', 'medium' ) as $s ) {
						if ( $in[ $s ] ) {
							$tally[] = sprintf( '%d %s', $in[ $s ], strtolower( self::sev_label( $s ) ) );
						}
					}
					self::door(
						__( 'Signs of a break-in', 'jat-shell-scanner' ),
						__( 'Files, accounts and logs', 'jat-shell-scanner' ),
						$in['state'],
						array(
							'clear'   => __( 'None found', 'jat-shell-scanner' ),
							'check'   => __( 'Worth a look', 'jat-shell-scanner' ),
							'suspect' => __( 'Suspicious', 'jat-shell-scanner' ),
							'breach'  => __( 'Break-in found', 'jat-shell-scanner' ),
						),
						array(
							'clear'   => __( 'No webshells, rogue admins or attack traces.', 'jat-shell-scanner' ),
							'check'   => implode( ', ', $tally ) . '.',
							'suspect' => implode( ', ', $tally ) . '.',
							'breach'  => implode( ', ', $tally ) . '.',
						)
					);
					?>
				</div>
			<?php endif; ?>
		</section>
		<?php
	}

	private static function door( $title, $sub, $state, $labels, $notes ) {
		$tone = array(
			'shut'    => 'ok',
			'clear'   => 'ok',
			'open'    => 'warn',
			'ask'     => 'warn',
			'check'   => 'warn',
			'suspect' => 'bad',
			'breach'  => 'bad',
			'unknown' => 'muted',
		);
		?>
		<div class="wp2ss-door wp2ss-tone-<?php echo esc_attr( isset( $tone[ $state ] ) ? $tone[ $state ] : 'muted' ); ?>">
			<p class="wp2ss-door-title"><?php echo esc_html( $title ); ?> <span><?php echo esc_html( $sub ); ?></span></p>
			<p class="wp2ss-door-state"><?php echo esc_html( isset( $labels[ $state ] ) ? $labels[ $state ] : '' ); ?></p>
			<p class="wp2ss-door-note"><?php echo esc_html( isset( $notes[ $state ] ) ? $notes[ $state ] : '' ); ?></p>
		</div>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* What to do next                                                     */
	/* ------------------------------------------------------------------ */

	private static function render_next_steps( $report, $ignored ) {
		list( $php, $wp, $in ) = self::doors( $report['findings'], $ignored );
		$fixable = self::bulk_fixable( $report, $ignored );
		$admins  = 0;
		foreach ( $report['findings'] as $f ) {
			$fix = WP2SS_Scanner::is_ignored( $f, $ignored ) || WP2SS_Fixes::record_for_finding( $f ) ? null : WP2SS_Fixes::fix_for( $f );
			if ( $fix && 'demote' === $fix['action'] && WP2SS_Scanner::sev_rank( $f['severity'] ) >= 4 ) {
				$admins++;
			}
		}
		$incident = in_array( $in['state'], array( 'breach', 'suspect' ), true );

		$steps = array();
		if ( $incident ) {
			$steps[] = array( __( 'Back up the whole site first', 'jat-shell-scanner' ), __( 'Files and database, with your host’s backup tool or a backup plugin. It’s your evidence and your undo button.', 'jat-shell-scanner' ), '' );
		}
		if ( in_array( $php['state'], array( 'open', 'ask' ), true ) ) {
			$steps[] = array( 'open' === $php['state'] ? __( 'Ask your host to update PHP', 'jat-shell-scanner' ) : __( 'Ask your host to confirm PHP is patched', 'jat-shell-scanner' ), __( 'On most hosting plans only they can. Here’s a message to send them:', 'jat-shell-scanner' ), 'host' );
		}
		if ( 'open' === $wp['state'] ) {
			$steps[] = array( __( 'Update WordPress', 'jat-shell-scanner' ), __( 'Dashboard → Updates. It takes a minute.', 'jat-shell-scanner' ), 'wp' );
		}
		if ( $fixable ) {
			/* translators: %d: number of items */
			$steps[] = array( sprintf( _n( 'Quarantine %d flagged item', 'Quarantine %d flagged items', count( $fixable ), 'jat-shell-scanner' ), count( $fixable ) ), __( 'They’re moved somewhere they can’t run. Nothing is deleted, and each one can be restored from the Quarantine tab.', 'jat-shell-scanner' ), 'fix_all' );
		}
		if ( $admins ) {
			/* translators: %d: number of accounts */
			$steps[] = array( sprintf( _n( 'Check %d unexpected administrator', 'Check %d unexpected administrators', $admins, 'jat-shell-scanner' ), $admins ), __( 'If you don’t know an account, use “Remove admin rights” next to it in the findings below.', 'jat-shell-scanner' ), '' );
		}
		if ( $incident || ( 'open' === $php['state'] ) ) {
			$steps[] = array( __( 'Change every password and secret key', 'jat-shell-scanner' ), __( 'Admin passwords, the database password, API keys in plugins, and the salts in wp-config.php. PHP2Shell can leak these from memory.', 'jat-shell-scanner' ), 'salts' );
		}
		if ( $steps ) {
			$steps[] = array( __( 'Scan again', 'jat-shell-scanner' ), __( 'Repeat until both doors are shut and no signs are left.', 'jat-shell-scanner' ), '' );
		}
		?>
		<section class="wp2ss-next" aria-labelledby="wp2ss-next-h">
			<h2 id="wp2ss-next-h"><?php echo $steps ? esc_html__( 'What to do next', 'jat-shell-scanner' ) : esc_html__( 'Nothing to do', 'jat-shell-scanner' ); ?></h2>
			<?php if ( ! $steps ) : ?>
				<p><?php echo esc_html( 'off' !== WP2SS_Settings::get()['schedule'] ? __( 'Automatic scans are on, and you’ll get an email if that changes.', 'jat-shell-scanner' ) : __( 'Automatic scans are off — turn them on in Settings so you hear about problems.', 'jat-shell-scanner' ) ); ?></p>
			<?php else : ?>
				<ol class="wp2ss-steps">
					<?php foreach ( $steps as $s ) : ?>
						<li>
							<strong><?php echo esc_html( $s[0] ); ?></strong>
							<span><?php echo esc_html( $s[1] ); ?></span>
							<?php
							switch ( $s[2] ) {
								case 'host':
									self::render_host_message( $report );
									break;
								case 'wp':
									if ( current_user_can( 'update_core' ) ) {
										echo ' <a class="button button-small" href="' . esc_url( network_admin_url( 'update-core.php' ) ) . '">' . esc_html__( 'Open WordPress updates', 'jat-shell-scanner' ) . '</a>';
									}
									break;
								case 'fix_all':
									?>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wp2ss-inline-form" data-confirm="<?php echo esc_attr( sprintf( /* translators: %d: count */ _n( 'Quarantine %d item now? You can restore it from the Quarantine tab.', 'Quarantine %d items now? You can restore them from the Quarantine tab.', count( $fixable ), 'jat-shell-scanner' ), count( $fixable ) ) ); ?>">
										<?php wp_nonce_field( 'wp2ss_fix_all' ); ?>
										<input type="hidden" name="action" value="wp2ss_fix_all">
										<button class="button button-small"><?php esc_html_e( 'Quarantine them', 'jat-shell-scanner' ); ?></button>
									</form>
									<?php
									break;
								case 'salts':
									echo ' <a class="button button-small" href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Get new salts', 'jat-shell-scanner' ) . '</a>';
									break;
							}
							?>
						</li>
					<?php endforeach; ?>
				</ol>
			<?php endif; ?>
		</section>
		<?php
	}

	/** Critical/high findings with a quarantine fix that hasn't been applied. */
	private static function bulk_fixable( $report, $ignored ) {
		$out = array();
		foreach ( $report['findings'] as $f ) {
			if ( WP2SS_Scanner::sev_rank( $f['severity'] ) < 4 || WP2SS_Scanner::is_ignored( $f, $ignored ) || WP2SS_Fixes::record_for_finding( $f ) ) {
				continue;
			}
			$fix = WP2SS_Fixes::fix_for( $f );
			if ( $fix && 'demote' !== $fix['action'] ) {
				$out[ $fix['target'] ] = $f['id']; // One entry per path, even if several findings point at it.
			}
		}
		return $out;
	}

	/** A ready-to-send support message, because most site owners can't update PHP themselves. */
	private static function render_host_message( $report ) {
		$env   = WP2SS_Env::get();
		$sig   = WP2SS_Scanner::signatures();
		$fixed = isset( $sig['php_fixed'][ $env['branch'] ] ) ? $sig['php_fixed'][ $env['branch'] ] : '8.2.35 or newer';
		$ver   = $env['version'] . ( ! empty( $env['pkg'] ) ? ' (package ' . $env['pkg'] . ')' : '' );
		$msg   = sprintf(
			/* translators: 1: site URL, 2: PHP version, 3: server API, 4: fixed version */
			__( "Hello,\n\nMy website %1\$s runs PHP %2\$s (%3\$s). A security scan says this version may be affected by PHP2Shell (CVE-2026-109618 and CVE-2026-109619), the critical PHP vulnerabilities announced on October 21, 2026.\n\nCould you please:\n1. Update PHP for my site to %4\$s (or your patched package), or confirm that the fix for both CVEs has already been applied to this server, and\n2. Restart PHP afterwards, and\n3. Until then, consider the temporary protections from PHP's advisory (memory_limit = -1 enforced with php_admin_value, session.upload_progress.enabled = 0, a low post_max_size and max_input_nesting_level, pm.max_requests = 1) in php.ini or the PHP-FPM pool. These only partly protect.\n\nCould you also let me know whether you've seen any signs of these attacks against my site since October 17, 2026?\n\nThank you!", 'jat-shell-scanner' ),
			$report['site'],
			$ver,
			self::sapi_label( $env['sapi'] ),
			$fixed
		);
		?>
		<div class="wp2ss-host">
			<textarea id="wp2ss-host-msg" class="large-text" rows="9" readonly aria-label="<?php esc_attr_e( 'Message for your host', 'jat-shell-scanner' ); ?>"><?php echo esc_textarea( $msg ); ?></textarea>
			<p>
				<button type="button" class="button button-primary wp2ss-copy" data-target="wp2ss-host-msg"><?php esc_html_e( 'Copy message', 'jat-shell-scanner' ); ?></button>
				<span class="description"><?php esc_html_e( 'Some hosts let you pick a newer PHP yourself: look for “PHP version” or “MultiPHP” in your hosting control panel and choose 8.2 or newer.', 'jat-shell-scanner' ); ?></span>
			</p>
		</div>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Findings tab                                                        */
	/* ------------------------------------------------------------------ */

	public static function area( $type ) {
		$map = array(
			'php'       => __( 'PHP (PHP2Shell)', 'jat-shell-scanner' ),
			'version'   => __( 'WordPress (wp2shell)', 'jat-shell-scanner' ),
			'user'      => __( 'Accounts', 'jat-shell-scanner' ),
			'code'      => __( 'Files and code', 'jat-shell-scanner' ),
			'hash'      => __( 'Files and code', 'jat-shell-scanner' ),
			'file'      => __( 'Files and code', 'jat-shell-scanner' ),
			'plugin'    => __( 'Plugins', 'jat-shell-scanner' ),
			'mu-plugin' => __( 'Plugins', 'jat-shell-scanner' ),
			'rest'      => __( 'Plugins', 'jat-shell-scanner' ),
			'core'      => __( 'WordPress core files', 'jat-shell-scanner' ),
			'database'  => __( 'Database', 'jat-shell-scanner' ),
			'log'       => __( 'Server logs', 'jat-shell-scanner' ),
			'scan'      => __( 'About this scan', 'jat-shell-scanner' ),
		);
		return isset( $map[ $type ] ) ? $map[ $type ] : $type;
	}

	private static function render_findings( $report, $ignored ) {
		$groups = array();
		$count  = array( 'action' => 0, 'all' => 0, 'ignored' => 0 );
		foreach ( $report['findings'] as $f ) {
			$is_ign = WP2SS_Scanner::is_ignored( $f, $ignored );
			$needs  = ! $is_ign && WP2SS_Scanner::sev_rank( $f['severity'] ) >= 3 && ! WP2SS_Fixes::record_for_finding( $f );
			$f['_state'] = $is_ign ? 'ignored' : ( $needs ? 'action' : 'other' );
			$groups[ self::area( $f['type'] ) ][] = $f;
			$count['all'] += $is_ign ? 0 : 1;
			$count['action'] += $needs ? 1 : 0;
			$count['ignored'] += $is_ign ? 1 : 0;
		}
		$order = array( 'PHP (PHP2Shell)', 'WordPress (wp2shell)', 'Files and code', 'Database', 'Accounts', 'Plugins', 'WordPress core files', 'Server logs', 'About this scan' );
		uksort(
			$groups,
			function ( $a, $b ) use ( $order ) {
				$x = array_search( $a, $order, true );
				$y = array_search( $b, $order, true );
				return ( false === $x ? 99 : $x ) - ( false === $y ? 99 : $y );
			}
		);
		$filter = $count['action'] ? 'action' : 'all';
		?>
		<div class="wp2ss-filter" role="group" aria-label="<?php esc_attr_e( 'Show', 'jat-shell-scanner' ); ?>" data-default="<?php echo esc_attr( $filter ); ?>">
			<button type="button" class="button" data-filter="action" aria-pressed="<?php echo 'action' === $filter ? 'true' : 'false'; ?>">
				<?php /* translators: %d: count */ printf( esc_html__( 'Needs action (%d)', 'jat-shell-scanner' ), (int) $count['action'] ); ?>
			</button>
			<button type="button" class="button" data-filter="all" aria-pressed="<?php echo 'all' === $filter ? 'true' : 'false'; ?>">
				<?php /* translators: %d: count */ printf( esc_html__( 'Everything (%d)', 'jat-shell-scanner' ), (int) $count['all'] ); ?>
			</button>
			<?php if ( $count['ignored'] ) : ?>
				<button type="button" class="button" data-filter="ignored" aria-pressed="false">
					<?php /* translators: %d: count */ printf( esc_html__( 'Ignored (%d)', 'jat-shell-scanner' ), (int) $count['ignored'] ); ?>
				</button>
			<?php endif; ?>
		</div>
		<p class="wp2ss-empty wp2ss-empty-action" <?php echo $count['action'] ? 'hidden' : ''; ?>><?php esc_html_e( 'Nothing needs your attention. “Everything” lists what the scan looked at.', 'jat-shell-scanner' ); ?></p>

		<div class="wp2ss-findings" data-filter="<?php echo esc_attr( $filter ); ?>">
			<?php foreach ( $groups as $area => $rows ) : ?>
				<section class="wp2ss-group">
					<h3><?php echo esc_html( $area ); ?></h3>
					<ul>
						<?php foreach ( $rows as $f ) : ?>
							<?php self::finding_row( $f ); ?>
						<?php endforeach; ?>
					</ul>
				</section>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/** Paths inside the site are shown from the site's folder, which is what owners see in a file manager. */
	private static function short_path( $p ) {
		$root = WP2SS_Paths::core();
		$norm = wp_normalize_path( $p );
		return 0 === strpos( $norm, $root . '/' ) ? substr( $norm, strlen( $root ) + 1 ) : $p;
	}

	private static function finding_row( $f ) {
		$loc     = (string) $f['location'];
		$applied = WP2SS_Fixes::record_for_finding( $f );
		$fix     = ( 'ignored' === $f['_state'] || $applied ) ? null : WP2SS_Fixes::fix_for( $f );
		?>
		<li class="wp2ss-f wp2ss-s-<?php echo esc_attr( $f['severity'] ); ?>" data-state="<?php echo esc_attr( $applied ? 'fixed' : $f['_state'] ); ?>" data-id="<?php echo esc_attr( $f['id'] ); ?>">
			<span class="wp2ss-sev"><?php echo esc_html( self::sev_label( $f['severity'] ) ); ?></span>
			<div class="wp2ss-f-body">
				<p class="wp2ss-f-msg"><?php echo esc_html( $f['message'] ); ?></p>
				<?php if ( 0 === strpos( $loc, 'user:' ) && get_edit_user_link( (int) substr( $loc, 5 ) ) ) : ?>
					<a class="wp2ss-loc" href="<?php echo esc_url( get_edit_user_link( (int) substr( $loc, 5 ) ) ); ?>"><?php esc_html_e( 'Open this account', 'jat-shell-scanner' ); ?></a>
				<?php elseif ( $loc && ! preg_match( '/^(user|rest|role):/', $loc ) ) : ?>
					<code class="wp2ss-loc"><?php echo esc_html( self::short_path( $loc ) ); ?></code>
				<?php endif; ?>
				<?php if ( $f['advice'] ) : ?>
					<p class="wp2ss-f-advice"><?php echo esc_html( $f['advice'] ); ?></p>
				<?php endif; ?>
				<?php if ( $applied ) : ?>
					<p class="wp2ss-f-done">
						<?php echo esc_html( 'demote' === $applied['action'] ? __( 'Admin rights removed.', 'jat-shell-scanner' ) : __( 'Quarantined.', 'jat-shell-scanner' ) ); ?>
						<button type="button" class="button-link wp2ss-undo" data-record="<?php echo esc_attr( $applied['id'] ); ?>"><?php esc_html_e( 'Undo', 'jat-shell-scanner' ); ?></button>
					</p>
				<?php endif; ?>
			</div>
			<div class="wp2ss-f-actions">
				<?php if ( $fix ) : ?>
					<button type="button" class="button wp2ss-fix" data-id="<?php echo esc_attr( $f['id'] ); ?>" data-confirm="<?php echo esc_attr( $fix['confirm'] ); ?>"><?php echo esc_html( $fix['label'] ); ?></button>
				<?php endif; ?>
				<?php if ( 'info' !== $f['severity'] && ! $applied ) : ?>
					<button type="button" class="button-link wp2ss-toggle" data-id="<?php echo esc_attr( $f['id'] ); ?>" data-ignore="<?php echo 'ignored' === $f['_state'] ? '0' : '1'; ?>">
						<?php 'ignored' === $f['_state'] ? esc_html_e( 'Stop ignoring', 'jat-shell-scanner' ) : esc_html_e( 'Ignore — it’s mine', 'jat-shell-scanner' ); ?>
					</button>
				<?php endif; ?>
			</div>
		</li>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Quarantine tab                                                      */
	/* ------------------------------------------------------------------ */

	private static function render_quarantine() {
		$records = WP2SS_Fixes::records();
		?>
		<p class="wp2ss-lede"><?php esc_html_e( 'Everything a fix changed is listed here and can be undone. Quarantined files sit in a private folder, renamed so they can’t run.', 'jat-shell-scanner' ); ?></p>
		<?php if ( ! WP2SS_Fixes::files_allowed() ) : ?>
			<div class="notice notice-info inline"><p><?php esc_html_e( 'This site doesn’t allow plugins to change files (DISALLOW_FILE_MODS), so only account fixes are available. Remove flagged files with your host’s file manager.', 'jat-shell-scanner' ); ?></p></div>
		<?php endif; ?>
		<?php if ( ! $records ) : ?>
			<p class="wp2ss-empty"><?php esc_html_e( 'Nothing has been quarantined or changed. Fixes appear next to findings that have one.', 'jat-shell-scanner' ); ?></p>
			<?php
			return;
		endif;
		?>
		<table class="widefat striped wp2ss-qtable">
			<thead><tr>
				<th><?php esc_html_e( 'What', 'jat-shell-scanner' ); ?></th>
				<th><?php esc_html_e( 'When', 'jat-shell-scanner' ); ?></th>
				<th><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'jat-shell-scanner' ); ?></span></th>
			</tr></thead>
			<tbody>
			<?php foreach ( array_reverse( $records ) as $r ) : ?>
				<tr>
					<td>
						<strong><?php echo esc_html( 'demote' === $r['action'] ? sprintf( /* translators: %s: login */ __( 'Removed admin rights from “%s”', 'jat-shell-scanner' ), $r['login'] ) : __( 'Quarantined', 'jat-shell-scanner' ) ); ?></strong>
						<?php if ( 'demote' !== $r['action'] ) : ?>
							<code class="wp2ss-loc"><?php echo esc_html( self::short_path( $r['original'] ) ); ?></code>
						<?php endif; ?>
						<p class="wp2ss-f-advice"><?php echo esc_html( $r['message'] ); ?></p>
					</td>
					<td><?php echo esc_html( sprintf( /* translators: %s: time ago */ __( '%s ago', 'jat-shell-scanner' ), human_time_diff( (int) $r['at'] ) ) ); ?></td>
					<td class="wp2ss-q-actions">
						<button type="button" class="button wp2ss-undo" data-record="<?php echo esc_attr( $r['id'] ); ?>"><?php echo esc_html( 'demote' === $r['action'] ? __( 'Give admin rights back', 'jat-shell-scanner' ) : __( 'Restore', 'jat-shell-scanner' ) ); ?></button>
						<?php if ( 'demote' !== $r['action'] ) : ?>
							<button type="button" class="button-link button-link-delete wp2ss-purge" data-record="<?php echo esc_attr( $r['id'] ); ?>"><?php esc_html_e( 'Delete for good', 'jat-shell-scanner' ); ?></button>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Fleet tab                                                           */
	/* ------------------------------------------------------------------ */

	private static function render_fleet() {
		$s = WP2SS_Fleet::settings();
		?>
		<p class="wp2ss-lede"><?php esc_html_e( 'Look after several sites? Make one of them the hub, and the others send it their result after every scan — one list of every site, on your own server.', 'jat-shell-scanner' ); ?></p>
		<?php
		if ( 'hub' === $s['mode'] ) {
			self::render_fleet_hub( $s );
		} elseif ( 'member' === $s['mode'] ) {
			self::render_fleet_member( $s );
		}
		?>
		<details class="wp2ss-fleet-setup" <?php echo 'off' === $s['mode'] ? 'open' : ''; ?>>
			<summary><?php echo 'off' === $s['mode'] ? esc_html__( 'Set up a fleet', 'jat-shell-scanner' ) : esc_html__( 'Change fleet settings', 'jat-shell-scanner' ); ?></summary>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wp2ss-fleet-form">
				<?php wp_nonce_field( 'wp2ss_fleet' ); ?>
				<input type="hidden" name="action" value="wp2ss_fleet">
				<fieldset>
					<legend class="screen-reader-text"><?php esc_html_e( 'Role of this site', 'jat-shell-scanner' ); ?></legend>
					<label class="wp2ss-choice"><input type="radio" name="mode" value="off" <?php checked( $s['mode'], 'off' ); ?>> <strong><?php esc_html_e( 'Not part of a fleet', 'jat-shell-scanner' ); ?></strong></label>
					<label class="wp2ss-choice"><input type="radio" name="mode" value="hub" <?php checked( $s['mode'], 'hub' ); ?>> <strong><?php esc_html_e( 'This site is the hub', 'jat-shell-scanner' ); ?></strong> <span><?php esc_html_e( 'It collects results from your other sites and shows them here.', 'jat-shell-scanner' ); ?></span></label>
					<label class="wp2ss-choice"><input type="radio" name="mode" value="member" <?php checked( $s['mode'], 'member' ); ?>> <strong><?php esc_html_e( 'Report to a hub', 'jat-shell-scanner' ); ?></strong> <span><?php esc_html_e( 'Send this site’s results to the hub after every scan.', 'jat-shell-scanner' ); ?></span></label>
				</fieldset>
				<div class="wp2ss-member-fields">
					<p>
						<label for="wp2ss-hub"><strong><?php esc_html_e( 'Hub site address', 'jat-shell-scanner' ); ?></strong></label><br>
						<input type="url" id="wp2ss-hub" name="hub" class="regular-text" value="<?php echo esc_attr( 'member' === $s['mode'] ? $s['hub'] : '' ); ?>" placeholder="https://hub.example.com">
					</p>
					<p>
						<label for="wp2ss-key"><strong><?php esc_html_e( 'Fleet key', 'jat-shell-scanner' ); ?></strong></label><br>
						<input type="password" id="wp2ss-key" name="key" class="regular-text code" value="" placeholder="<?php echo esc_attr( 'member' === $s['mode'] && $s['key'] ? __( 'Saved — leave blank to keep it', 'jat-shell-scanner' ) : '' ); ?>" autocomplete="off">
						<br><span class="description"><?php esc_html_e( 'Shown on the hub’s Fleet tab.', 'jat-shell-scanner' ); ?></span>
					</p>
				</div>
				<?php submit_button( __( 'Save fleet settings', 'jat-shell-scanner' ), 'primary', 'submit', false ); ?>
			</form>
		</details>
		<?php
	}

	private static function render_fleet_hub( $s ) {
		$sites   = WP2SS_Fleet::sites();
		$tally   = array_count_values( wp_list_pluck( $sites, 'verdict' ) );
		$order   = array( 'COMPROMISED', 'SUSPICIOUS', 'VULNERABLE', 'REVIEW', 'CLEAN' );
		$join    = sprintf( 'wp php2shell fleet join %s %s', network_home_url(), $s['key'] );
		?>
		<div class="wp2ss-fleet-summary">
			<?php foreach ( $order as $v ) : ?>
				<?php if ( ! empty( $tally[ $v ] ) ) : ?>
					<span class="wp2ss-chip wp2ss-v-<?php echo esc_attr( strtolower( $v ) ); ?>"><?php echo esc_html( $tally[ $v ] . ' ' . self::verdict_label( $v ) ); ?></span>
				<?php endif; ?>
			<?php endforeach; ?>
			<?php if ( $sites ) : ?>
				<span class="wp2ss-fleet-tools">
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-confirm="<?php esc_attr_e( 'Ask every site to scan again? Each one starts within an hour.', 'jat-shell-scanner' ); ?>">
						<?php wp_nonce_field( 'wp2ss_fleet_rescan' ); ?>
						<input type="hidden" name="action" value="wp2ss_fleet_rescan">
						<button class="button button-small"><?php esc_html_e( 'Ask all sites to scan', 'jat-shell-scanner' ); ?></button>
					</form>
					<a class="button button-small" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wp2ss_fleet_csv' ), 'wp2ss_fleet_csv' ) ); ?>"><?php esc_html_e( 'Download as CSV', 'jat-shell-scanner' ); ?></a>
				</span>
			<?php endif; ?>
		</div>

		<?php if ( ! $sites ) : ?>
			<p class="wp2ss-empty"><?php esc_html_e( 'No sites have reported yet. Connect your other sites with the key below, then scan them.', 'jat-shell-scanner' ); ?></p>
		<?php else : ?>
			<table class="widefat wp2ss-fleet">
				<thead><tr>
					<th><?php esc_html_e( 'Site', 'jat-shell-scanner' ); ?></th>
					<th><?php esc_html_e( 'Result', 'jat-shell-scanner' ); ?></th>
					<th><?php esc_html_e( 'PHP', 'jat-shell-scanner' ); ?></th>
					<th><?php esc_html_e( 'WordPress', 'jat-shell-scanner' ); ?></th>
					<th><?php esc_html_e( 'Last report', 'jat-shell-scanner' ); ?></th>
					<th><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'jat-shell-scanner' ); ?></span></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $sites as $key => $site ) : ?>
					<tr class="wp2ss-v-<?php echo esc_attr( strtolower( $site['verdict'] ) ); ?>">
						<td>
							<strong><a href="<?php echo esc_url( $site['admin'] ? $site['admin'] : $site['site'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $site['name'] ? $site['name'] : $site['site'] ); ?></a></strong>
							<span class="wp2ss-fleet-url"><?php echo esc_html( preg_replace( '#^https?://#', '', $site['site'] ) ); ?></span>
							<?php if ( ! empty( $site['legacy'] ) ) : ?>
								<span class="wp2ss-legacy"><?php esc_html_e( 'Older scanner version: update it so only this site can report for this address.', 'jat-shell-scanner' ); ?></span>
							<?php endif; ?>
							<?php if ( $site['serious'] ) : ?>
								<details class="wp2ss-fleet-details">
									<summary><?php /* translators: %d: count */ printf( esc_html( _n( '%d serious finding', '%d serious findings', count( $site['serious'] ), 'jat-shell-scanner' ) ), count( $site['serious'] ) ); ?></summary>
									<ul>
										<?php foreach ( $site['serious'] as $f ) : ?>
											<li class="wp2ss-s-<?php echo esc_attr( $f['severity'] ); ?>"><?php echo esc_html( $f['message'] ); ?></li>
										<?php endforeach; ?>
									</ul>
								</details>
							<?php endif; ?>
						</td>
						<td><span class="wp2ss-chip wp2ss-v-<?php echo esc_attr( strtolower( $site['verdict'] ) ); ?>"><?php echo esc_html( $site['label'] ? $site['label'] : self::verdict_label( $site['verdict'] ) ); ?></span></td>
						<td><?php echo esc_html( $site['php'] ); ?></td>
						<td><?php echo esc_html( $site['wp'] ); ?></td>
						<td class="<?php echo WP2SS_Fleet::is_stale( $site ) ? 'wp2ss-stale' : ''; ?>">
							<?php echo esc_html( sprintf( /* translators: %s: time ago */ __( '%s ago', 'jat-shell-scanner' ), human_time_diff( (int) $site['received'] ) ) ); ?>
							<?php if ( WP2SS_Fleet::is_stale( $site ) ) : ?>
								<br><?php esc_html_e( 'Overdue', 'jat-shell-scanner' ); ?>
							<?php endif; ?>
							<?php if ( ! empty( $site['rescan'] ) ) : ?>
								<br><span class="wp2ss-pending"><?php esc_html_e( 'Scan requested', 'jat-shell-scanner' ); ?></span>
							<?php endif; ?>
						</td>
						<td class="wp2ss-fleet-actions">
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
								<?php wp_nonce_field( 'wp2ss_fleet_rescan' ); ?>
								<input type="hidden" name="action" value="wp2ss_fleet_rescan">
								<input type="hidden" name="site" value="<?php echo esc_attr( $key ); ?>">
								<button class="button-link"><?php esc_html_e( 'Scan again', 'jat-shell-scanner' ); ?></button>
							</form>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-confirm="<?php esc_attr_e( 'Remove this site from the list? It reappears if it reports again.', 'jat-shell-scanner' ); ?>">
								<?php wp_nonce_field( 'wp2ss_fleet_forget' ); ?>
								<input type="hidden" name="action" value="wp2ss_fleet_forget">
								<input type="hidden" name="site" value="<?php echo esc_attr( $key ); ?>">
								<button class="button-link button-link-delete"><?php esc_html_e( 'Remove', 'jat-shell-scanner' ); ?></button>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>

		<?php self::render_fleet_alerts( $s ); ?>

		<section class="wp2ss-connect">
			<h3><?php esc_html_e( 'Connect your other sites', 'jat-shell-scanner' ); ?></h3>
			<p><?php esc_html_e( 'On each site: install this plugin, open its Fleet tab, choose “Report to a hub”, and paste this address and key.', 'jat-shell-scanner' ); ?></p>
			<p><label><?php esc_html_e( 'Hub address', 'jat-shell-scanner' ); ?><br><input type="text" class="regular-text code" id="wp2ss-hub-url" value="<?php echo esc_attr( network_home_url() ); ?>" readonly></label>
				<button type="button" class="button wp2ss-copy" data-target="wp2ss-hub-url"><?php esc_html_e( 'Copy', 'jat-shell-scanner' ); ?></button></p>
			<p><label><?php esc_html_e( 'Fleet key', 'jat-shell-scanner' ); ?><br><input type="text" class="regular-text code" id="wp2ss-fleet-key" value="<?php echo esc_attr( $s['key'] ); ?>" readonly></label>
				<button type="button" class="button wp2ss-copy" data-target="wp2ss-fleet-key"><?php esc_html_e( 'Copy', 'jat-shell-scanner' ); ?></button></p>
			<p><?php esc_html_e( 'With WP-CLI, one command per site does it:', 'jat-shell-scanner' ); ?></p>
			<p><input type="text" class="large-text code" id="wp2ss-join" value="<?php echo esc_attr( $join ); ?>" readonly>
				<button type="button" class="button wp2ss-copy" data-target="wp2ss-join"><?php esc_html_e( 'Copy command', 'jat-shell-scanner' ); ?></button></p>
			<p class="description"><?php esc_html_e( 'Keep the key private: anyone with it can add a site to this list (they can’t read anything, or report for a site that has already registered). If it leaks, make a new one — then give the new key to every site.', 'jat-shell-scanner' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-confirm="<?php esc_attr_e( 'Make a new fleet key? Every member site will need the new key before it can report again.', 'jat-shell-scanner' ); ?>">
				<?php wp_nonce_field( 'wp2ss_fleet_rotate' ); ?>
				<input type="hidden" name="action" value="wp2ss_fleet_rotate">
				<button class="button"><?php esc_html_e( 'Make a new key', 'jat-shell-scanner' ); ?></button>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-confirm="<?php esc_attr_e( 'Empty the whole list? Sites reappear with their next report.', 'jat-shell-scanner' ); ?>">
				<?php wp_nonce_field( 'wp2ss_fleet_clear' ); ?>
				<input type="hidden" name="action" value="wp2ss_fleet_clear">
				<button class="button-link button-link-delete"><?php esc_html_e( 'Empty the list', 'jat-shell-scanner' ); ?></button>
			</form>
			<?php if ( 0 !== strpos( network_home_url(), 'https://' ) ) : ?>
				<div class="notice notice-warning inline"><p><?php esc_html_e( 'This hub isn’t on HTTPS. Reports are signed, so they can’t be forged, but anyone on the network path could read them. Use HTTPS if you can.', 'jat-shell-scanner' ); ?></p></div>
			<?php endif; ?>
		</section>
		<?php
	}

	private static function render_fleet_alerts( $s ) {
		$default = WP2SS_Settings::alert_email();
		?>
		<section class="wp2ss-alerts">
			<h3><?php esc_html_e( 'Alerts', 'jat-shell-scanner' ); ?></h3>
			<p><?php esc_html_e( 'Get one message when sites need a look: a site gets worse, a new site joins in trouble, or a site stops reporting. Several sites at once arrive as a single digest.', 'jat-shell-scanner' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wp2ss_fleet_alerts' ); ?>
				<input type="hidden" name="action" value="wp2ss_fleet_alerts">
				<p>
					<label><input type="checkbox" name="alert_email" value="1" <?php checked( $s['alert_email'] ); ?>> <?php esc_html_e( 'Email me', 'jat-shell-scanner' ); ?></label>
					<input type="email" name="alert_to" class="regular-text" value="<?php echo esc_attr( $s['alert_to'] ); ?>" placeholder="<?php echo esc_attr( $default ); ?>" aria-label="<?php esc_attr_e( 'Alert email address', 'jat-shell-scanner' ); ?>">
				</p>
				<p>
					<label for="wp2ss-webhook"><strong><?php esc_html_e( 'Slack or Discord webhook', 'jat-shell-scanner' ); ?></strong> <span class="description"><?php esc_html_e( '(optional)', 'jat-shell-scanner' ); ?></span></label><br>
					<input type="url" id="wp2ss-webhook" name="alert_webhook" class="large-text code" value="<?php echo esc_attr( $s['alert_webhook'] ); ?>" placeholder="https://hooks.slack.com/services/…" autocomplete="off">
					<br><span class="description"><?php esc_html_e( 'In Slack: Apps → Incoming Webhooks. In Discord: channel settings → Integrations → Webhooks.', 'jat-shell-scanner' ); ?></span>
				</p>
				<p>
					<label><input type="checkbox" name="alert_stale" value="1" <?php checked( $s['alert_stale'] ); ?>> <?php esc_html_e( 'Also tell me when a site hasn’t reported for', 'jat-shell-scanner' ); ?></label>
					<input type="number" name="stale_days" min="2" max="90" class="small-text" value="<?php echo esc_attr( $s['stale_days'] ); ?>" aria-label="<?php esc_attr_e( 'Days', 'jat-shell-scanner' ); ?>"> <?php esc_html_e( 'days', 'jat-shell-scanner' ); ?>
				</p>
				<p class="wp2ss-inline-buttons">
					<?php submit_button( __( 'Save alerts', 'jat-shell-scanner' ), 'secondary', 'submit', false ); ?>
					<button class="button" name="test" value="1"><?php esc_html_e( 'Save and send a test', 'jat-shell-scanner' ); ?></button>
				</p>
			</form>
		</section>
		<?php
	}

	private static function render_fleet_member( $s ) {
		$st = get_site_option( WP2SS_Fleet::STATUS );
		?>
		<div class="wp2ss-member">
			<p>
				<?php
				/* translators: %s: hub URL */
				printf( esc_html__( 'This site reports to %s after every scan.', 'jat-shell-scanner' ), '<strong>' . esc_html( $s['hub'] ) . '</strong>' );
				?>
			</p>
			<?php if ( is_array( $st ) ) : ?>
				<p class="<?php echo $st['ok'] ? 'wp2ss-ok' : 'wp2ss-bad'; ?>">
					<?php
					echo esc_html(
						$st['ok']
							? sprintf( /* translators: %s: time ago */ __( 'Last report delivered %s ago.', 'jat-shell-scanner' ), human_time_diff( (int) $st['at'] ) )
							: sprintf( /* translators: 1: time ago, 2: error */ __( 'The last report %1$s ago didn’t arrive: %2$s', 'jat-shell-scanner' ), human_time_diff( (int) $st['at'] ), $st['detail'] ? $st['detail'] : 'HTTP ' . $st['code'] )
					);
					?>
				</p>
			<?php endif; ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wp2ss_fleet_send' ); ?>
				<input type="hidden" name="action" value="wp2ss_fleet_send">
				<button class="button"><?php esc_html_e( 'Send the latest result now', 'jat-shell-scanner' ); ?></button>
			</form>
		</div>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Settings tab                                                        */
	/* ------------------------------------------------------------------ */

	private static function render_settings() {
		$s         = WP2SS_Settings::get();
		$env       = WP2SS_Env::get();
		$next      = wp_next_scheduled( WP2SS_Cron::HOOK );
		$schedules = array(
			'off'    => __( 'Off', 'jat-shell-scanner' ),
			'daily'  => __( 'Daily', 'jat-shell-scanner' ),
			'weekly' => __( 'Weekly', 'jat-shell-scanner' ),
		);
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wp2ss-settings">
			<?php wp_nonce_field( 'wp2ss_settings' ); ?>
			<input type="hidden" name="action" value="wp2ss_settings">
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="wp2ss-schedule"><?php esc_html_e( 'Automatic scans', 'jat-shell-scanner' ); ?></label></th>
					<td>
						<select id="wp2ss-schedule" name="schedule">
							<?php foreach ( $schedules as $k => $label ) : ?>
								<option value="<?php echo esc_attr( $k ); ?>" <?php selected( $s['schedule'], $k ); ?>><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
						<?php if ( $next && 'off' !== $s['schedule'] ) : ?>
							<p class="description"><?php /* translators: %s: time */ printf( esc_html__( 'Next scan in %s.', 'jat-shell-scanner' ), esc_html( human_time_diff( $next ) ) ); ?></p>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Email alerts', 'jat-shell-scanner' ); ?></th>
					<td>
						<label><input type="checkbox" name="email" value="1" <?php checked( $s['email'] ); ?>> <?php esc_html_e( 'Email me when an automatic scan finds something new and serious', 'jat-shell-scanner' ); ?></label><br>
						<input type="email" name="email_to" class="regular-text" value="<?php echo esc_attr( $s['email_to'] ); ?>" placeholder="<?php echo esc_attr( get_site_option( 'admin_email' ) ); ?>" aria-label="<?php esc_attr_e( 'Alert email address', 'jat-shell-scanner' ); ?>">
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Core and plugin files', 'jat-shell-scanner' ); ?></th>
					<td><label><input type="checkbox" name="core" value="1" <?php checked( $s['core'] ); ?>> <?php esc_html_e( 'Compare WordPress’s own files, and plugins from wordpress.org, with the official copies', 'jat-shell-scanner' ); ?></label></td>
				</tr>
				<tr>
					<th scope="row"><label for="wp2ss-errlog"><?php esc_html_e( 'PHP error log', 'jat-shell-scanner' ); ?></label></th>
					<td>
						<input type="text" id="wp2ss-errlog" name="error_log" class="regular-text code" value="<?php echo esc_attr( $s['error_log'] ); ?>" placeholder="<?php echo esc_attr( $env['error_log'] ? $env['error_log'] : __( 'found automatically', 'jat-shell-scanner' ) ); ?>">
						<p class="description"><?php esc_html_e( 'Where PHP2Shell attempts show up. Leave empty to use the log PHP reports, plus WordPress’s debug.log.', 'jat-shell-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="wp2ss-log"><?php esc_html_e( 'Web server access log', 'jat-shell-scanner' ); ?></label></th>
					<td>
						<input type="text" id="wp2ss-log" name="log" class="regular-text code" value="<?php echo esc_attr( $s['log'] ); ?>" placeholder="/var/log/nginx/access.log">
						<p class="description"><?php esc_html_e( 'Optional. If PHP can read it, scans also look for attack traffic. .gz files work.', 'jat-shell-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'This website’s PHP', 'jat-shell-scanner' ); ?></th>
					<td>
						<p>
							<?php
							printf(
								/* translators: 1: PHP version, 2: server type, 3: operating system */
								esc_html__( 'PHP %1$s on %2$s (%3$s)', 'jat-shell-scanner' ),
								esc_html( $env['version'] ),
								esc_html( self::sapi_label( $env['sapi'] ) ),
								esc_html( $env['os'] )
							);
							?>
						</p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Save settings', 'jat-shell-scanner' ) ); ?>
		</form>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Labels                                                              */
	/* ------------------------------------------------------------------ */

	public static function sapi_label( $sapi ) {
		$l = array(
			'apache2handler' => 'Apache mod_php',
			'fpm-fcgi'       => 'PHP-FPM',
			'cgi-fcgi'       => 'FastCGI',
			'litespeed'      => 'LiteSpeed',
			'frankenphp'     => 'FrankenPHP',
			'cli'            => 'command line',
			'cli-server'     => 'built-in server',
		);
		return isset( $l[ $sapi ] ) ? $l[ $sapi ] : $sapi;
	}

	public static function sev_label( $s ) {
		$l = array(
			'critical' => __( 'Critical', 'jat-shell-scanner' ),
			'high'     => __( 'High', 'jat-shell-scanner' ),
			'medium'   => __( 'Medium', 'jat-shell-scanner' ),
			'low'      => __( 'Low', 'jat-shell-scanner' ),
			'info'     => __( 'Info', 'jat-shell-scanner' ),
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
				return __( 'Vulnerable — update PHP and WordPress', 'jat-shell-scanner' );
			}
			if ( $php ) {
				return __( 'Vulnerable — PHP needs updating', 'jat-shell-scanner' );
			}
			if ( $wp ) {
				return __( 'Vulnerable — update WordPress', 'jat-shell-scanner' );
			}
			return __( 'Vulnerable', 'jat-shell-scanner' );
		}
		$l = array(
			'COMPROMISED' => __( 'Compromised', 'jat-shell-scanner' ),
			'SUSPICIOUS'  => __( 'Suspicious', 'jat-shell-scanner' ),
			'REVIEW'      => __( 'Needs review', 'jat-shell-scanner' ),
			'CLEAN'       => __( 'No signs of PHP2Shell or wp2shell', 'jat-shell-scanner' ),
		);
		return isset( $l[ $v ] ) ? $l[ $v ] : $v;
	}

	public static function verdict_help( $v, $findings = array() ) {
		if ( 'VULNERABLE' === $v ) {
			return self::has_vuln( $findings, 'php' )
				? __( 'No signs of a break-in, but this server’s PHP can be attacked through PHP2Shell. Ask your host to update it — there’s a message ready to send on the scanner page.', 'jat-shell-scanner' )
				: __( 'No signs of a break-in, but this WordPress version can be attacked through wp2shell. Update it now.', 'jat-shell-scanner' );
		}
		$l = array(
			'COMPROMISED' => __( 'Strong evidence of an attack. Open the scanner for step-by-step help.', 'jat-shell-scanner' ),
			'SUSPICIOUS'  => __( 'Something here needs a closer look today.', 'jat-shell-scanner' ),
			'REVIEW'      => __( 'A few things to confirm, nothing alarming on its own.', 'jat-shell-scanner' ),
			'CLEAN'       => __( 'No known indicators found. Keep PHP and WordPress updated.', 'jat-shell-scanner' ),
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
				<strong><?php echo esc_html( sprintf( /* translators: %s: verdict */ __( 'PHP2Shell Scanner: %s', 'jat-shell-scanner' ), self::verdict_label( $v, $r['findings'] ) ) ); ?></strong> —
				<?php echo esc_html( self::verdict_help( $v, $r['findings'] ) ); ?>
				<a href="<?php echo esc_url( self::url() ); ?>"><?php esc_html_e( 'See what to do', 'jat-shell-scanner' ); ?></a>
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

	public static function ajax_fix() {
		self::ajax_guard();
		$id = isset( $_POST['id'] ) ? preg_replace( '/[^a-f0-9]/', '', sanitize_text_field( wp_unslash( $_POST['id'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		$r  = WP2SS_Fixes::apply( $id, get_current_user_id() );
		if ( is_wp_error( $r ) ) {
			self::json( false, array( 'message' => $r->get_error_message() ) );
		}
		self::json( true, array( 'record' => $r['id'] ) );
	}

	public static function ajax_undo() {
		self::ajax_guard();
		$id = isset( $_POST['record'] ) ? preg_replace( '/[^a-z0-9]/', '', sanitize_text_field( wp_unslash( $_POST['record'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		$r  = WP2SS_Fixes::undo( $id );
		if ( is_wp_error( $r ) ) {
			self::json( false, array( 'message' => $r->get_error_message() ) );
		}
		self::json( true );
	}

	public static function ajax_purge() {
		self::ajax_guard();
		$id = isset( $_POST['record'] ) ? preg_replace( '/[^a-z0-9]/', '', sanitize_text_field( wp_unslash( $_POST['record'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		$r  = WP2SS_Fixes::purge( $id );
		if ( is_wp_error( $r ) ) {
			self::json( false, array( 'message' => $r->get_error_message() ) );
		}
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
		self::back( 'findings', array(), false );
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
		self::back( 'settings', array( 'done' => 'saved' ) );
	}

	/** Quarantine every critical/high item that has a file fix. */
	public static function post_fix_all() {
		self::guard( 'wp2ss_fix_all' );
		$report = WP2SS_Scanner::last_report();
		$errors = array();
		if ( $report ) {
			foreach ( self::bulk_fixable( $report, WP2SS_Scanner::ignored() ) as $finding_id ) {
				$r = WP2SS_Fixes::apply( $finding_id, get_current_user_id() );
				if ( is_wp_error( $r ) ) {
					$errors[] = $r->get_error_message();
				}
			}
		}
		self::back( 'findings', $errors ? array( 'err' => implode( ' ', array_unique( $errors ) ) ) : array( 'done' => 'fixed' ) );
	}

	public static function post_fleet() {
		self::guard( 'wp2ss_fleet' );
		// phpcs:disable WordPress.Security.NonceVerification
		$mode = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : 'off';
		$hub  = isset( $_POST['hub'] ) ? esc_url_raw( wp_unslash( $_POST['hub'] ) ) : '';
		$key  = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		// phpcs:enable
		$r = WP2SS_Fleet::save( $mode, $hub, $key );
		if ( is_wp_error( $r ) ) {
			self::back( 'fleet', array( 'err' => $r->get_error_message() ) );
		}
		if ( 'member' === $mode && WP2SS_Scanner::last_report() ) {
			$sent = WP2SS_Fleet::send();
			if ( is_wp_error( $sent ) ) {
				self::back( 'fleet', array( 'err' => $sent->get_error_message() ) );
			}
		}
		self::back( 'fleet', array( 'done' => 'fleet' ) );
	}

	public static function post_fleet_send() {
		self::guard( 'wp2ss_fleet_send' );
		$r = WP2SS_Fleet::send();
		self::back( 'fleet', is_wp_error( $r ) ? array( 'err' => $r->get_error_message() ) : array( 'done' => 'sent' ) );
	}

	public static function post_fleet_rotate() {
		self::guard( 'wp2ss_fleet_rotate' );
		WP2SS_Fleet::rotate_key();
		self::back( 'fleet', array( 'done' => 'rotated' ) );
	}

	public static function post_fleet_forget() {
		self::guard( 'wp2ss_fleet_forget' );
		$key = isset( $_POST['site'] ) ? preg_replace( '/[^a-f0-9]/', '', sanitize_text_field( wp_unslash( $_POST['site'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		WP2SS_Fleet::forget( $key );
		self::back( 'fleet', array( 'done' => 'forgot' ) );
	}

	public static function post_fleet_alerts() {
		self::guard( 'wp2ss_fleet_alerts' );
		// phpcs:disable WordPress.Security.NonceVerification
		$r    = WP2SS_Fleet::save_alerts(
			! empty( $_POST['alert_email'] ),
			isset( $_POST['alert_to'] ) ? sanitize_email( wp_unslash( $_POST['alert_to'] ) ) : '',
			isset( $_POST['alert_webhook'] ) ? esc_url_raw( wp_unslash( $_POST['alert_webhook'] ), array( 'https' ) ) : '',
			! empty( $_POST['alert_stale'] ),
			isset( $_POST['stale_days'] ) ? absint( $_POST['stale_days'] ) : 15
		);
		$test = ! empty( $_POST['test'] );
		// phpcs:enable
		if ( is_wp_error( $r ) ) {
			self::back( 'fleet', array( 'err' => $r->get_error_message() ) );
		}
		if ( $test ) {
			self::post_fleet_test( false );
		}
		self::back( 'fleet', array( 'done' => 'alerts' ) );
	}

	public static function post_fleet_test( $check = true ) {
		if ( false !== $check ) {
			self::guard( 'wp2ss_fleet_test' );
		}
		$t = WP2SS_Fleet::test_alert();
		self::back( 'fleet', is_wp_error( $t ) ? array( 'err' => $t->get_error_message() ) : array( 'done' => 'tested' ) );
	}

	public static function post_fleet_rescan() {
		self::guard( 'wp2ss_fleet_rescan' );
		$key = isset( $_POST['site'] ) ? preg_replace( '/[^a-f0-9]/', '', sanitize_text_field( wp_unslash( $_POST['site'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		WP2SS_Fleet::request_rescan( $key ? $key : null );
		self::back( 'fleet', array( 'done' => 'rescan' ) );
	}

	public static function post_fleet_clear() {
		self::guard( 'wp2ss_fleet_clear' );
		WP2SS_Fleet::clear();
		self::back( 'fleet', array( 'done' => 'cleared' ) );
	}

	public static function post_fleet_csv() {
		self::guard( 'wp2ss_fleet_csv' );
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="php2shell-fleet-' . gmdate( 'Ymd' ) . '.csv"' );
		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fputcsv( $out, array( 'site', 'name', 'verdict', 'php', 'wordpress', 'critical', 'high', 'medium', 'scanned', 'received' ) );
		foreach ( WP2SS_Fleet::sites() as $s ) {
			// Neutralise spreadsheet formulas in values that came from other sites.
			$cell = function ( $v ) {
				$v = (string) $v;
				return preg_match( '/^[=+\-@\t\r]/', $v ) ? "'" . $v : $v;
			};
			fputcsv( $out, array_map( $cell, array( $s['site'], $s['name'], $s['verdict'], $s['php'], $s['wp'], $s['counts']['critical'], $s['counts']['high'], $s['counts']['medium'], $s['scanned'], gmdate( 'c', (int) $s['received'] ) ) ) );
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}
}
