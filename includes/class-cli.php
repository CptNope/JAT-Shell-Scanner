<?php
/**
 * WP-CLI commands.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Check this site for PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and
 * wp2shell (CVE-2026-63030 / CVE-2026-60137): exposure and signs of a break-in.
 */
class WP2SS_CLI {

	/**
	 * Run a scan.
	 *
	 * ## OPTIONS
	 *
	 * [--log=<path>]
	 * : Access log to check for attack traffic (.gz works). Defaults to the path saved in settings.
	 *
	 * [--error-log=<path>]
	 * : PHP error log to check for PHP2Shell attempts. Defaults to the setting, then the log PHP reports.
	 *
	 * [--skip-core]
	 * : Skip verifying core files against wordpress.org.
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
	 *   - yaml
	 *   - summary
	 * ---
	 *
	 * [--include-ignored]
	 * : Also show findings marked as ignored in the dashboard.
	 *
	 * ## EXAMPLES
	 *
	 *     wp php2shell scan
	 *     wp php2shell scan --log=/var/log/nginx/access.log --min=medium
	 *     wp php2shell scan --format=json > report.json
	 *     wp @all php2shell scan --format=summary
	 *
	 * Exit code: 0 = clean or review, 1 = vulnerable or suspicious, 2 = compromised.
	 *
	 * Note: WP-CLI often runs a different PHP than the website. The PHP check
	 * uses the website's PHP as last seen from the dashboard, if available.
	 *
	 * @when after_wp_load
	 */
	public function scan( $args, $assoc ) {
		$settings = WP2SS_Settings::scan_args();
		$scan     = array(
			'log'       => isset( $assoc['log'] ) ? $assoc['log'] : $settings['log'],
			'error_log' => isset( $assoc['error-log'] ) ? $assoc['error-log'] : $settings['error_log'],
			'core'      => empty( $assoc['skip-core'] ) && $settings['core'],
		);
		$format   = WP_CLI\Utils\get_flag_value( $assoc, 'format', 'table' );
		$quiet    = in_array( $format, array( 'json', 'csv', 'yaml', 'summary' ), true );

		$progress = null;
		if ( ! $quiet ) {
			$progress = WP_CLI\Utils\make_progress_bar( 'Scanning', 100 );
		}
		$last = 0;

		$report = WP2SS_Scanner::run_all(
			$scan,
			'cli',
			function ( $state ) use ( $progress, &$last ) {
				if ( $progress ) {
					$p = (int) $state['progress'];
					if ( $p > $last ) {
						$progress->tick( $p - $last );
						$last = $p;
					}
				}
			}
		);
		if ( $progress ) {
			$progress->tick( 100 - $last );
			$progress->finish();
		}

		$ignored  = WP2SS_Scanner::ignored();
		$min      = WP2SS_Scanner::sev_rank( WP_CLI\Utils\get_flag_value( $assoc, 'min', 'low' ) );
		$show_ign = WP_CLI\Utils\get_flag_value( $assoc, 'include-ignored', false );
		$verdict  = WP2SS_Scanner::verdict( $report['findings'], $ignored );
		$rows     = array();
		foreach ( $report['findings'] as $f ) {
			$is_ign = WP2SS_Scanner::is_ignored( $f, $ignored );
			if ( WP2SS_Scanner::sev_rank( $f['severity'] ) < $min || ( $is_ign && ! $show_ign ) ) {
				continue;
			}
			$f['ignored'] = $is_ign ? 'yes' : '';
			$rows[]       = $f;
		}

		if ( 'json' === $format ) {
			$report['verdict']  = $verdict;
			$report['findings'] = $rows;
			WP_CLI::line( wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
		} elseif ( 'summary' === $format ) {
			$c = array();
			foreach ( $report['findings'] as $f ) {
				if ( ! WP2SS_Scanner::is_ignored( $f, $ignored ) ) {
					$c[ $f['severity'] ] = isset( $c[ $f['severity'] ] ) ? $c[ $f['severity'] ] + 1 : 1;
				}
			}
			WP_CLI::line(
				sprintf(
					'%-12s %-45s wp %-8s php %-10s critical:%d high:%d medium:%d',
					$verdict,
					$report['site'],
					$report['wp'],
					isset( $report['php']['version'] ) ? $report['php']['version'] : '?',
					isset( $c['critical'] ) ? $c['critical'] : 0,
					isset( $c['high'] ) ? $c['high'] : 0,
					isset( $c['medium'] ) ? $c['medium'] : 0
				)
			);
		} else {
			if ( $rows ) {
				WP_CLI\Utils\format_items( $format, $rows, array( 'severity', 'type', 'message', 'location', 'id' ) );
			}
			$line = sprintf( '%s — %s (%s PHP files, %ss)', $report['site'], WP2SS_Admin::verdict_label( $verdict, $report['findings'] ), number_format( $report['stats']['php_files'] ), $report['duration'] );
			if ( in_array( $verdict, array( 'CLEAN', 'REVIEW' ), true ) ) {
				WP_CLI::success( $line );
			} else {
				WP_CLI::warning( $line );
			}
		}

		if ( 'COMPROMISED' === $verdict ) {
			WP_CLI::halt( 2 );
		}
		if ( 'SUSPICIOUS' === $verdict || 'VULNERABLE' === $verdict ) {
			WP_CLI::halt( 1 );
		}
	}

	/**
	 * Mark a finding as a false positive (or undo that).
	 *
	 * ## OPTIONS
	 *
	 * <id>...
	 * : Finding ID(s), from the `id` column of `wp wp2shell scan`.
	 *
	 * [--undo]
	 * : Stop ignoring these findings.
	 *
	 * ## EXAMPLES
	 *
	 *     wp php2shell ignore 3f9a1c2b7d10
	 */
	public function ignore( $args, $assoc ) {
		foreach ( $args as $id ) {
			WP2SS_Scanner::set_ignored( $id, empty( $assoc['undo'] ) );
		}
		WP_CLI::success( sprintf( '%d finding(s) %s.', count( $args ), empty( $assoc['undo'] ) ? 'ignored' : 'restored' ) );
	}

	/**
	 * Show the result of the last scan without scanning again.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json or summary.
	 * ---
	 * default: summary
	 * ---
	 */
	public function status( $args, $assoc ) {
		$r = WP2SS_Scanner::last_report();
		if ( ! $r ) {
			WP_CLI::error( 'No scan has been run yet. Try: wp php2shell scan' );
		}
		$verdict = WP2SS_Scanner::verdict( $r['findings'] );
		$format  = WP_CLI\Utils\get_flag_value( $assoc, 'format', 'summary' );
		if ( 'json' === $format ) {
			$r['verdict'] = $verdict;
			WP_CLI::line( wp_json_encode( $r, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			return;
		}
		if ( 'table' === $format ) {
			WP_CLI\Utils\format_items( 'table', $r['findings'], array( 'severity', 'type', 'message', 'id' ) );
		}
		WP_CLI::line( sprintf( '%s — %s, scanned %s (%s)', $r['site'], WP2SS_Admin::verdict_label( $verdict, $r['findings'] ), $r['scanned'], $r['source'] ) );
	}

	/**
	 * Apply the one-click fix for a finding (quarantine a file or plugin, or remove admin rights).
	 *
	 * Every fix can be undone with `wp php2shell quarantine restore <id>`.
	 *
	 * ## OPTIONS
	 *
	 * [<id>...]
	 * : Finding ID(s), from the `id` column of `wp php2shell scan`.
	 *
	 * [--all-critical]
	 * : Fix every critical and high finding that has a file fix (like the dashboard's "Quarantine them" button).
	 *
	 * [--yes]
	 * : Don't ask for confirmation.
	 *
	 * ## EXAMPLES
	 *
	 *     wp php2shell fix 3f9a1c2b7d10
	 *     wp php2shell fix --all-critical --yes
	 */
	public function fix( $args, $assoc ) {
		$report = WP2SS_Scanner::last_report();
		if ( ! $report ) {
			WP_CLI::error( 'Run a scan first: wp php2shell scan' );
		}
		$ids = $args;
		if ( ! empty( $assoc['all-critical'] ) ) {
			$ignored = WP2SS_Scanner::ignored();
			foreach ( $report['findings'] as $f ) {
				$fix = WP2SS_Fixes::fix_for( $f );
				if ( $fix && 'demote' !== $fix['action'] && WP2SS_Scanner::sev_rank( $f['severity'] ) >= 4 && ! WP2SS_Scanner::is_ignored( $f, $ignored ) && ! WP2SS_Fixes::record_for_finding( $f['id'] ) ) {
					$ids[ $fix['target'] ] = $f['id'];
				}
			}
			$ids = array_values( array_unique( $ids ) );
		}
		if ( ! $ids ) {
			WP_CLI::success( 'Nothing to fix.' );
			return;
		}
		WP_CLI::confirm( sprintf( 'Apply %d fix(es)? Each can be undone with `wp php2shell quarantine restore`.', count( $ids ) ), $assoc );
		$failed = 0;
		foreach ( $ids as $id ) {
			$r = WP2SS_Fixes::apply( $id, 0 );
			if ( is_wp_error( $r ) ) {
				$failed++;
				WP_CLI::warning( "$id: " . $r->get_error_message() );
			} else {
				WP_CLI::log( sprintf( '%s: %s (undo id %s)', $id, 'demote' === $r['action'] ? 'admin rights removed from ' . $r['login'] : 'quarantined ' . $r['original'], $r['id'] ) );
			}
		}
		$failed ? WP_CLI::error( "$failed fix(es) failed." ) : WP_CLI::success( 'Done.' );
	}

	/**
	 * List, restore or delete quarantined items and other fixes.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : list, restore or delete.
	 * ---
	 * options:
	 *   - list
	 *   - restore
	 *   - delete
	 * ---
	 *
	 * [<id>]
	 * : The undo id shown by `list` (for restore and delete).
	 *
	 * [--yes]
	 * : Don't ask before deleting.
	 *
	 * [--format=<format>]
	 * : For list: table, json or csv.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp php2shell quarantine list
	 *     wp php2shell quarantine restore k3j9x0p2q7ab
	 *     wp php2shell quarantine delete k3j9x0p2q7ab --yes
	 */
	public function quarantine( $args, $assoc ) {
		$action = $args[0];
		if ( 'list' === $action ) {
			$rows = array();
			foreach ( WP2SS_Fixes::records() as $r ) {
				$rows[] = array(
					'id'     => $r['id'],
					'action' => $r['action'],
					'target' => 'demote' === $r['action'] ? 'user ' . $r['login'] : $r['original'],
					'when'   => gmdate( 'Y-m-d H:i', (int) $r['at'] ),
				);
			}
			if ( ! $rows ) {
				WP_CLI::log( 'Nothing quarantined.' );
				return;
			}
			WP_CLI\Utils\format_items( WP_CLI\Utils\get_flag_value( $assoc, 'format', 'table' ), $rows, array( 'id', 'action', 'target', 'when' ) );
			return;
		}
		if ( empty( $args[1] ) ) {
			WP_CLI::error( 'Give the id from `wp php2shell quarantine list`.' );
		}
		if ( 'delete' === $action ) {
			WP_CLI::confirm( 'Delete it for good? This can’t be undone.', $assoc );
		}
		$r = 'restore' === $action ? WP2SS_Fixes::undo( $args[1] ) : WP2SS_Fixes::purge( $args[1] );
		is_wp_error( $r ) ? WP_CLI::error( $r->get_error_message() ) : WP_CLI::success( 'restore' === $action ? 'Restored.' : 'Deleted.' );
	}

	/**
	 * Fleet: report this site to a hub, or manage a hub.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : join, leave, send, status, hub or list.
	 * ---
	 * options:
	 *   - join
	 *   - leave
	 *   - send
	 *   - status
	 *   - hub
	 *   - list
	 * ---
	 *
	 * [<hub-url>]
	 * : For join: the hub site's address.
	 *
	 * [<key>]
	 * : For join: the fleet key shown on the hub.
	 *
	 * [--format=<format>]
	 * : For list: table, json or csv.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # On the hub site
	 *     wp php2shell fleet hub
	 *     wp php2shell fleet list
	 *
	 *     # On every other site
	 *     wp php2shell fleet join https://hub.example.com 3kd9…
	 *     wp @all php2shell fleet join https://hub.example.com 3kd9…
	 */
	public function fleet( $args, $assoc ) {
		$action = $args[0];
		switch ( $action ) {
			case 'join':
				if ( count( $args ) < 3 ) {
					WP_CLI::error( 'Usage: wp php2shell fleet join <hub-url> <key>' );
				}
				$r = WP2SS_Fleet::save( 'member', $args[1], $args[2] );
				if ( is_wp_error( $r ) ) {
					WP_CLI::error( $r->get_error_message() );
				}
				if ( WP2SS_Scanner::last_report() ) {
					$sent = WP2SS_Fleet::send();
					is_wp_error( $sent ) ? WP_CLI::warning( 'Joined, but the first report failed: ' . $sent->get_error_message() ) : WP_CLI::success( 'Joined the fleet and sent the latest result.' );
				} else {
					WP_CLI::success( 'Joined the fleet. Results will be sent after the next scan.' );
				}
				break;

			case 'leave':
				WP2SS_Fleet::save( 'off' );
				WP_CLI::success( 'This site no longer reports to a hub.' );
				break;

			case 'send':
				$r = WP2SS_Fleet::send();
				is_wp_error( $r ) ? WP_CLI::error( $r->get_error_message() ) : WP_CLI::success( 'Sent.' );
				break;

			case 'hub':
				$s = WP2SS_Fleet::save( 'hub' );
				WP_CLI::success( 'This site is now the fleet hub.' );
				WP_CLI::log( 'Run this on each of your other sites:' );
				WP_CLI::log( sprintf( '  wp php2shell fleet join %s %s', network_home_url(), $s['key'] ) );
				break;

			case 'list':
				$rows = array();
				foreach ( WP2SS_Fleet::sites() as $site ) {
					$rows[] = array(
						'site'     => $site['site'],
						'verdict'  => $site['verdict'],
						'php'      => $site['php'],
						'wp'       => $site['wp'],
						'critical' => $site['counts']['critical'],
						'high'     => $site['counts']['high'],
						'reported' => human_time_diff( (int) $site['received'] ) . ' ago' . ( WP2SS_Fleet::is_stale( $site ) ? ' (overdue)' : '' ),
					);
				}
				if ( ! $rows ) {
					WP_CLI::log( 'No sites have reported yet.' );
					return;
				}
				WP_CLI\Utils\format_items( WP_CLI\Utils\get_flag_value( $assoc, 'format', 'table' ), $rows, array_keys( $rows[0] ) );
				break;

			default: // status
				$s = WP2SS_Fleet::settings();
				WP_CLI::log( 'Mode: ' . $s['mode'] . ( 'member' === $s['mode'] ? ' → ' . $s['hub'] : '' ) );
				$st = get_site_option( WP2SS_Fleet::STATUS );
				if ( is_array( $st ) ) {
					WP_CLI::log( sprintf( 'Last report: %s, %s ago%s', $st['ok'] ? 'delivered' : 'FAILED', human_time_diff( (int) $st['at'] ), $st['ok'] ? '' : ' — ' . $st['detail'] ) );
				}
		}
	}
}
