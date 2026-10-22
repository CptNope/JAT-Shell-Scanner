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
			'label' => __( 'wp2shell scan', 'wp2shell-scanner' ),
			'test'  => array( __CLASS__, 'test' ),
		);
		return $tests;
	}

	public static function test() {
		$r      = WP2SS_Scanner::last_report();
		$link   = sprintf( '<p><a href="%s">%s</a></p>', esc_url( WP2SS_Admin::url() ), esc_html__( 'Open wp2shell Scanner', 'wp2shell-scanner' ) );
		$result = array(
			'label'       => __( 'No signs of the wp2shell attack', 'wp2shell-scanner' ),
			'status'      => 'good',
			'badge'       => array( 'label' => __( 'Security', 'wp2shell-scanner' ), 'color' => 'blue' ),
			'description' => '<p>' . esc_html__( 'The last scan found no known indicators of wp2shell (CVE-2026-63030 / CVE-2026-60137).', 'wp2shell-scanner' ) . '</p>',
			'actions'     => $link,
			'test'        => 'wp2ss',
		);

		if ( ! $r ) {
			$result['label']       = __( 'This site hasn’t been scanned for wp2shell', 'wp2shell-scanner' );
			$result['status']      = 'recommended';
			$result['description'] = '<p>' . esc_html__( 'Run a scan to check for signs of the wp2shell attack on WordPress core.', 'wp2shell-scanner' ) . '</p>';
			return $result;
		}

		$v = WP2SS_Scanner::verdict( $r['findings'], (array) get_site_option( 'wp2ss_ignored', array() ) );
		if ( in_array( $v, array( 'COMPROMISED', 'SUSPICIOUS', 'VULNERABLE' ), true ) ) {
			$labels                   = array(
				'COMPROMISED' => __( 'The wp2shell scan found signs of compromise', 'wp2shell-scanner' ),
				'SUSPICIOUS'  => __( 'The wp2shell scan found something suspicious', 'wp2shell-scanner' ),
				'VULNERABLE'  => __( 'WordPress is vulnerable to wp2shell', 'wp2shell-scanner' ),
			);
			$result['label']          = $labels[ $v ];
			$result['status']         = 'critical';
			$result['badge']['color'] = 'red';
			$result['description']    = '<p>' . esc_html( WP2SS_Admin::verdict_help( $v ) ) . '</p>';
		} elseif ( 'REVIEW' === $v ) {
			$result['label']       = __( 'The wp2shell scan has items to review', 'wp2shell-scanner' );
			$result['status']      = 'recommended';
			$result['description'] = '<p>' . esc_html( WP2SS_Admin::verdict_help( $v ) ) . '</p>';
		}
		return $result;
	}
}
