<?php
/**
 * Site Health (Tools → Site Health) integration.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Site_Health {

	public static function init() {
		add_filter( 'site_status_tests', array( __CLASS__, 'register' ) );
	}

	public static function register( $tests ) {
		$tests['direct']['wp2ss'] = array(
			'label' => __( 'PHP2Shell and wp2shell scan', 'jat-shell-scanner' ),
			'test'  => array( __CLASS__, 'test' ),
		);
		return $tests;
	}

	public static function test() {
		$r      = WP2SS_Scanner::last_report();
		$link   = sprintf( '<p><a href="%s">%s</a></p>', esc_url( WP2SS_Admin::url() ), esc_html__( 'Open PHP2Shell Scanner', 'jat-shell-scanner' ) );
		$result = array(
			'label'       => __( 'No signs of PHP2Shell or wp2shell', 'jat-shell-scanner' ),
			'status'      => 'good',
			'badge'       => array( 'label' => __( 'Security', 'jat-shell-scanner' ), 'color' => 'blue' ),
			'description' => '<p>' . esc_html__( 'The last scan found no known indicators of PHP2Shell (CVE-2026-109618 / CVE-2026-109619) or wp2shell (CVE-2026-63030 / CVE-2026-60137).', 'jat-shell-scanner' ) . '</p>',
			'actions'     => $link,
			'test'        => 'wp2ss',
		);

		if ( ! $r ) {
			$result['label']       = __( 'This site hasn’t been scanned for PHP2Shell or wp2shell', 'jat-shell-scanner' );
			$result['status']      = 'recommended';
			$result['description'] = '<p>' . esc_html__( 'Run a scan to check whether this site is exposed to, or was broken into through, PHP2Shell or wp2shell.', 'jat-shell-scanner' ) . '</p>';
			return $result;
		}

		$v = WP2SS_Scanner::verdict( $r['findings'] );
		if ( in_array( $v, array( 'COMPROMISED', 'SUSPICIOUS', 'VULNERABLE' ), true ) ) {
			$labels                   = array(
				'COMPROMISED' => __( 'The PHP2Shell scan found signs of compromise', 'jat-shell-scanner' ),
				'SUSPICIOUS'  => __( 'The PHP2Shell scan found something suspicious', 'jat-shell-scanner' ),
				'VULNERABLE'  => WP2SS_Admin::verdict_label( $v, $r['findings'] ),
			);
			$result['label']          = $labels[ $v ];
			$result['status']         = 'critical';
			$result['badge']['color'] = 'red';
			$result['description']    = '<p>' . esc_html( WP2SS_Admin::verdict_help( $v ) ) . '</p>';
		} elseif ( 'REVIEW' === $v ) {
			$result['label']       = __( 'The PHP2Shell scan has items to review', 'jat-shell-scanner' );
			$result['status']      = 'recommended';
			$result['description'] = '<p>' . esc_html( WP2SS_Admin::verdict_help( $v ) ) . '</p>';
		}

		// A result that's much older than the schedule isn't worth much.
		$s   = WP2SS_Settings::get();
		$max = 'daily' === $s['schedule'] ? 2 * DAY_IN_SECONDS : ( 'weekly' === $s['schedule'] ? 2 * WEEK_IN_SECONDS : 30 * DAY_IN_SECONDS );
		if ( 'good' === $result['status'] && time() - strtotime( $r['scanned'] ) > $max ) {
			$result['label']       = __( 'The last PHP2Shell scan is out of date', 'jat-shell-scanner' );
			$result['status']      = 'recommended';
			$result['description'] = '<p>' . esc_html__( 'The last scan was clean but is old. Scan again to be sure.', 'jat-shell-scanner' ) . '</p>';
		}
		return $result;
	}
}
