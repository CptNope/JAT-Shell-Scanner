<?php
/**
 * Updates from GitHub releases, through the normal WordPress update screen.
 *
 * Looks at the latest published release of the repo, and if its version is
 * newer, offers the attached wp2shell-scanner.zip as an update. Results are
 * cached so the GitHub API is asked at most twice a day.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Updater {

	const REPO      = WP2SS_REPO;
	const ASSET     = 'wp2shell-scanner.zip';
	const TRANSIENT = 'wp2ss_release';

	public static function init() {
		// Agencies that manage plugin versions themselves can switch this off in wp-config.php.
		if ( defined( 'WP2SS_DISABLE_UPDATER' ) && WP2SS_DISABLE_UPDATER ) {
			return;
		}
		add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'inject' ) );
		add_filter( 'plugins_api', array( __CLASS__, 'info' ), 20, 3 );
		add_filter( 'upgrader_source_selection', array( __CLASS__, 'fix_folder' ), 10, 4 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'flush' ), 10, 2 );
	}

	/** Latest release, or null. */
	public static function release() {
		$cached = get_site_transient( self::TRANSIENT );
		if ( is_array( $cached ) ) {
			return empty( $cached['version'] ) ? null : $cached;
		}

		$res = wp_remote_get(
			'https://api.github.com/repos/' . self::REPO . '/releases/latest',
			array(
				'timeout' => 8,
				'headers' => array(
					'Accept'     => 'application/vnd.github+json',
					'User-Agent' => 'wp2shell-scanner/' . WP2SS_VERSION,
				),
			)
		);

		$data = null;
		if ( ! is_wp_error( $res ) && 200 === wp_remote_retrieve_response_code( $res ) ) {
			$json = json_decode( wp_remote_retrieve_body( $res ), true );
			if ( is_array( $json ) && ! empty( $json['tag_name'] ) && empty( $json['draft'] ) && empty( $json['prerelease'] ) ) {
				$package = '';
				foreach ( (array) ( isset( $json['assets'] ) ? $json['assets'] : array() ) as $a ) {
					if ( isset( $a['name'] ) && self::ASSET === $a['name'] ) {
						$package = $a['browser_download_url'];
					}
				}
				if ( $package && 0 === strpos( $package, 'https://github.com/' . self::REPO . '/releases/download/' ) ) {
					$data = array(
						'version'   => ltrim( $json['tag_name'], 'vV' ),
						'package'   => $package,
						'url'       => $json['html_url'],
						'notes'     => isset( $json['body'] ) ? (string) $json['body'] : '',
						'published' => isset( $json['published_at'] ) ? $json['published_at'] : '',
					);
				}
			}
		}

		// Cache success for 12h; failures for 1h so a GitHub outage doesn't hammer the API.
		set_site_transient( self::TRANSIENT, $data ? $data : array(), $data ? 12 * HOUR_IN_SECONDS : HOUR_IN_SECONDS );
		return $data;
	}

	public static function inject( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}
		// Never let an unrelated plugin with the same folder name (e.g. on wordpress.org) replace this one.
		unset( $transient->response[ WP2SS_BASENAME ], $transient->no_update[ WP2SS_BASENAME ] );
		$r = self::release();
		if ( ! $r ) {
			return $transient;
		}
		$item = (object) array(
			'id'           => 'github.com/' . self::REPO,
			'slug'         => 'wp2shell-scanner',
			'plugin'       => WP2SS_BASENAME,
			'new_version'  => $r['version'],
			'url'          => 'https://github.com/' . self::REPO,
			'package'      => $r['package'],
			'requires_php' => '7.0',
		);
		if ( version_compare( $r['version'], WP2SS_VERSION, '>' ) ) {
			$transient->response[ WP2SS_BASENAME ] = $item;
		} else {
			$transient->no_update[ WP2SS_BASENAME ] = $item;
		}
		return $transient;
	}

	public static function info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || empty( $args->slug ) || 'wp2shell-scanner' !== $args->slug ) {
			return $result;
		}
		$r = self::release();
		return (object) array(
			'name'          => 'JAT Shell Scanner',
			'slug'          => 'wp2shell-scanner',
			'version'       => $r ? $r['version'] : WP2SS_VERSION,
			'author'        => 'Jeremy Anderson',
			'homepage'      => 'https://github.com/' . self::REPO,
			'download_link' => $r ? $r['package'] : '',
			'requires'      => '6.0',
			'requires_php'  => '7.0',
			'last_updated'  => $r ? $r['published'] : '',
			'sections'      => array(
				'description' => esc_html__( 'Checks whether a site is exposed to, or was broken into through, PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and wp2shell (CVE-2026-63030 / CVE-2026-60137). Read-only.', 'jat-shell-scanner' ),
				'changelog'   => $r ? '<pre>' . esc_html( $r['notes'] ) . '</pre>' : '',
			),
		);
	}

	/**
	 * Keep the installed folder name across updates, whatever it was installed as
	 * (e.g. "PHP2Shell-WP-scanner-main" from a GitHub source download).
	 */
	public static function fix_folder( $source, $remote_source, $upgrader, $extra = array() ) {
		global $wp_filesystem;
		if ( empty( $extra['plugin'] ) || WP2SS_BASENAME !== $extra['plugin'] || ! $wp_filesystem ) {
			return $source;
		}
		$want = trailingslashit( $remote_source ) . dirname( WP2SS_BASENAME ) . '/';
		if ( untrailingslashit( $source ) === untrailingslashit( $want ) ) {
			return $source;
		}
		if ( $wp_filesystem->move( $source, $want, true ) ) {
			return $want;
		}
		return new WP_Error( 'wp2ss_rename', __( 'Could not prepare the update folder.', 'jat-shell-scanner' ) );
	}

	public static function flush( $upgrader, $extra ) {
		if ( isset( $extra['type'] ) && 'plugin' === $extra['type'] ) {
			delete_site_transient( self::TRANSIENT );
		}
	}
}
