<?php
/**
 * Where things are on this site, from WordPress's own functions.
 *
 * Every other file asks this class for locations. WordPress has functions
 * for themes, uploads, must-use plugins and this plugin; for its own core
 * folder and wp-content it has none, so those two are read here, in one
 * place. The scanner only reads them. The plugin writes in one place only:
 * its folder in uploads (see storage()).
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Paths {

	/** This plugin's folder in uploads, e.g. wp-content/uploads/jat-shell-scanner. */
	const STORAGE = 'jat-shell-scanner';

	/** Normalized, no trailing slash. */
	private static function clean( $path ) {
		return wp_normalize_path( untrailingslashit( (string) $path ) );
	}

	/** The same path with links resolved ('' if it doesn't exist). */
	public static function real( $path ) {
		$real = realpath( (string) $path );
		return $real ? self::clean( $real ) : '';
	}

	/**
	 * WordPress's own folder, where wp-admin, wp-includes and the core files
	 * live (the scanner compares these with WordPress's checksums). WordPress
	 * has no function for it.
	 */
	public static function core() {
		return self::clean( ABSPATH );
	}

	/**
	 * The content folder (wp-content, or wherever the site moved it). The
	 * scanner reads it because attackers hide files there. WordPress has no
	 * function for it.
	 */
	public static function content() {
		return self::clean( WP_CONTENT_DIR );
	}

	/** The plugins folder: the folder this plugin is installed in. */
	public static function plugins() {
		return self::clean( dirname( plugin_dir_path( WP2SS_FILE ) ) );
	}

	/** One installed plugin's folder (or its single file), by its basename such as "akismet/akismet.php". */
	public static function plugin( $basename ) {
		$basename = self::clean( $basename );
		$folder   = strtok( $basename, '/' );
		return self::plugins() . '/' . ( false !== strpos( $basename, '/' ) ? $folder : $basename );
	}

	/** The must-use plugins folder ('' if the site has none). */
	public static function mu_plugins() {
		// wp_get_mu_plugins() lists the loaded files; the folder is where they are.
		foreach ( wp_get_mu_plugins() as $file ) {
			return self::clean( dirname( $file ) );
		}
		return defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ? self::clean( WPMU_PLUGIN_DIR ) : '';
	}

	/** The themes folder (or a given theme's root, which can differ). */
	public static function themes( $stylesheet = '' ) {
		return self::clean( '' === $stylesheet ? get_theme_root() : get_theme_root( $stylesheet ) );
	}

	/** One theme's folder. */
	public static function theme( $stylesheet ) {
		return self::themes( $stylesheet ) . '/' . $stylesheet;
	}

	/** The uploads base folder (the main site's on multisite). */
	public static function uploads() {
		$up = wp_upload_dir( null, false );
		return empty( $up['basedir'] ) ? '' : self::clean( $up['basedir'] );
	}

	/** The PHP error log WordPress writes to when WP_DEBUG_LOG is on ('' if none). */
	public static function debug_log() {
		if ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && '' !== WP_DEBUG_LOG ) {
			return self::clean( WP_DEBUG_LOG );
		}
		// WordPress points PHP's error_log setting at the debug log when WP_DEBUG_LOG is true.
		$ini = (string) ini_get( 'error_log' );
		if ( '' !== $ini && 'syslog' !== $ini ) {
			return self::clean( $ini );
		}
		return self::content() . '/debug.log';
	}

	/** A file in wp-admin/includes, for loading WordPress admin functions. */
	public static function admin_file( $file ) {
		return self::core() . '/wp-admin/includes/' . basename( $file );
	}

	/** Load WordPress admin functions such as get_plugins() outside wp-admin. */
	public static function admin_include( $file ) {
		$path = self::admin_file( $file );
		if ( is_readable( $path ) ) {
			require_once $path;
		}
	}

	/**
	 * This plugin's own folder in uploads, where quarantined files go,
	 * blocked from the web (Apache, LiteSpeed, IIS) and with an empty index.
	 * Uses the main site's uploads on multisite, so there's one quarantine.
	 *
	 * @param bool $create Create it if it's missing.
	 * @return string '' if it doesn't exist (or can't be created).
	 */
	public static function storage( $create = false ) {
		$switched = is_multisite() && ! is_main_site();
		if ( $switched ) {
			switch_to_blog( get_main_site_id() );
		}
		$base = self::uploads();
		if ( $switched ) {
			restore_current_blog();
		}
		if ( '' === $base ) {
			return '';
		}
		$dir = $base . '/' . self::STORAGE;
		if ( $create && ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return '';
		}
		if ( $create ) {
			self::protect( $dir );
		}
		return is_dir( $dir ) ? $dir : '';
	}

	/** Block web access to a folder of this plugin's (files are renamed so they can't run, too). */
	public static function protect( $dir ) {
		$files = array(
			'.htaccess'  => "Require all denied\nDeny from all\n",
			'web.config' => '<?xml version="1.0"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>',
			'index.php'  => "<?php\n// Silence is golden.\n",
		);
		foreach ( $files as $name => $content ) {
			if ( ! file_exists( $dir . '/' . $name ) ) {
				@file_put_contents( $dir . '/' . $name, $content ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_put_contents_file_put_contents -- Protects the plugin's own folder in uploads.
			}
		}
	}
}
