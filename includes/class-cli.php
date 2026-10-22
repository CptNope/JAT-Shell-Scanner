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
}
