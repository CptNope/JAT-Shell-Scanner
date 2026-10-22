<?php
/**
 * One-click fixes, every one of them reversible.
 *
 * Scans never change anything. Fixes run only when an administrator clicks
 * one (or runs `wp php2shell fix`), and each can be undone:
 *
 *  - Quarantine: a flagged file or plugin folder is moved into a private,
 *    randomly named folder inside wp-content and renamed so it can't run.
 *    It can be restored to where it was, or deleted for good.
 *  - Remove admin rights: a flagged administrator is turned into a
 *    Subscriber (and loses super-admin on multisite). The old roles are kept
 *    so this can be undone.
 *
 * Every record is signed with the site's secret keys from wp-config.php, so
 * someone who can only write to the database can't plant a fake "restore"
 * that moves files where they like.
 *
 * @package WP2Shell_Scanner
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP2SS_Fixes {

	const OPTION     = 'wp2ss_fixes';
	const DIR_OPTION = 'wp2ss_quarantine_dir';

	/* ------------------------------------------------------------------ */
	/* What can be fixed                                                   */
	/* ------------------------------------------------------------------ */

	/** Can this site change files at all? */
	public static function files_allowed() {
		return ! ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS );
	}

	/**
	 * The fix offered for a finding, if any.
	 *
	 * @return array|null { action: quarantine|quarantine_plugin|demote, label, target, confirm }
	 */
	public static function fix_for( $f ) {
		$loc = (string) $f['location'];
		if ( WP2SS_Scanner::sev_rank( $f['severity'] ) < 3 ) {
			return null; // Only for medium and above.
		}

		// Administrators flagged as rogue.
		if ( 'user' === $f['type'] && 0 === strpos( $loc, 'user:' ) && false !== stripos( $f['message'], 'administrator' ) ) {
			$id = (int) substr( $loc, 5 );
			if ( $id && $id !== get_current_user_id() && get_userdata( $id ) ) {
				return array(
					'action'  => 'demote',
					'label'   => __( 'Remove admin rights', 'wp2shell-scanner' ),
					'target'  => $id,
					'confirm' => __( 'Turn this account into a Subscriber? It will lose all admin powers. You can undo this.', 'wp2shell-scanner' ),
				);
			}
			return null;
		}

		if ( ! self::files_allowed() || '' === $loc || '/' !== $loc[0] && ! preg_match( '#^[A-Za-z]:/#', $loc ) ) {
			return null;
		}

		// A whole plugin folder (wp2shell_<hex>, CMSmap, fake cache plugin, gg-…).
		if ( 'plugin' === $f['type'] ) {
			$plugin_dir = wp_normalize_path( untrailingslashit( WP_PLUGIN_DIR ) );
			$path       = wp_normalize_path( $loc );
			if ( 0 === strpos( $path, $plugin_dir . '/' ) ) {
				$folder = $plugin_dir . '/' . strtok( substr( $path, strlen( $plugin_dir ) + 1 ), '/' );
				if ( self::safe_target( $folder ) ) {
					return array(
						'action'  => 'quarantine_plugin',
						'label'   => __( 'Quarantine plugin', 'wp2shell-scanner' ),
						'target'  => $folder,
						'confirm' => __( 'Deactivate this plugin and move it into quarantine, where it can’t run? You can restore it later.', 'wp2shell-scanner' ),
					);
				}
			}
			return null;
		}

		// Single files: webshells, PHP in data folders, unknown files in core folders, staging folders.
		if ( in_array( $f['type'], array( 'file', 'code', 'hash', 'core' ), true ) ) {
			if ( 'core' === $f['type'] && false !== stripos( $f['message'], 'Modified WordPress core file' ) ) {
				return null; // Reinstall core instead — never move core files.
			}
			if ( self::safe_target( $loc ) ) {
				return array(
					'action'  => 'quarantine',
					'label'   => __( 'Quarantine', 'wp2shell-scanner' ),
					'target'  => wp_normalize_path( $loc ),
					'confirm' => __( 'Move this into quarantine, where it can’t run? You can restore it later.', 'wp2shell-scanner' ),
				);
			}
		}
		return null;
	}

	/**
	 * Is it safe to move this path? Only files and folders inside the site,
	 * never WordPress's own folders, wp-config.php, or this plugin itself.
	 */
	public static function safe_target( $path ) {
		$real = realpath( $path );
		if ( ! $real || ! file_exists( $real ) ) {
			return false;
		}
		$real    = wp_normalize_path( $real );
		$abs     = wp_normalize_path( untrailingslashit( (string) realpath( ABSPATH ) ) );
		$content = wp_normalize_path( untrailingslashit( (string) realpath( WP_CONTENT_DIR ) ) );
		$inside  = 0 === strpos( $real . '/', $abs . '/' ) || 0 === strpos( $real . '/', $content . '/' );
		if ( ! $inside ) {
			$plugins = wp_normalize_path( untrailingslashit( (string) realpath( WP_PLUGIN_DIR ) ) );
			$inside  = $plugins && 0 === strpos( $real . '/', $plugins . '/' );
		}
		if ( ! $inside ) {
			return false;
		}
		$never = array(
			$abs,
			$content,
			$abs . '/wp-admin',
			$abs . '/wp-includes',
			$abs . '/wp-config.php',
			dirname( $abs ) . '/wp-config.php',
			$abs . '/index.php',
			$abs . '/wp-load.php',
			$abs . '/wp-settings.php',
			$abs . '/wp-blog-header.php',
			$content . '/plugins',
			$content . '/themes',
			$content . '/uploads',
			$content . '/mu-plugins',
			wp_normalize_path( untrailingslashit( (string) realpath( WP_PLUGIN_DIR ) ) ),
			wp_normalize_path( untrailingslashit( (string) realpath( WP2SS_DIR ) ) ),
			self::qdir(),
		);
		if ( in_array( $real, $never, true ) ) {
			return false;
		}
		// Nothing inside this plugin's own folder except files it doesn't ship (handled by the finding itself).
		$self = wp_normalize_path( untrailingslashit( (string) realpath( WP2SS_DIR ) ) );
		if ( 0 === strpos( $real . '/', $self . '/' ) && is_dir( $real ) ) {
			return false;
		}
		// Whole theme folders are too big a hammer; single files inside them are fine.
		$themes = wp_normalize_path( untrailingslashit( (string) realpath( get_theme_root() ) ) );
		if ( is_dir( $real ) && dirname( $real ) === $themes ) {
			return false;
		}
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Quarantine folder                                                   */
	/* ------------------------------------------------------------------ */

	/** The private quarantine folder (created on first use). */
	public static function qdir( $create = false ) {
		$name = get_site_option( self::DIR_OPTION );
		if ( ! $name || ! preg_match( '/^wp2ss-quarantine-[a-z0-9]{16}$/', $name ) ) {
			if ( ! $create ) {
				return '';
			}
			$name = 'wp2ss-quarantine-' . strtolower( wp_generate_password( 16, false ) );
			update_site_option( self::DIR_OPTION, $name );
		}
		$dir = wp_normalize_path( untrailingslashit( WP_CONTENT_DIR ) ) . '/' . $name;
		if ( $create && ! is_dir( $dir ) ) {
			if ( ! wp_mkdir_p( $dir ) ) {
				return '';
			}
			// Belt and braces: block web access on Apache, LiteSpeed and IIS. Files are also renamed so nothing can execute.
			@file_put_contents( $dir . '/.htaccess', "Require all denied\nDeny from all\n" ); // phpcs:ignore
			@file_put_contents( $dir . '/web.config', '<?xml version="1.0"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>' ); // phpcs:ignore
			@file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore
		}
		return $dir;
	}

	/* ------------------------------------------------------------------ */
	/* Records                                                             */
	/* ------------------------------------------------------------------ */

	private static function sign( $r ) {
		unset( $r['sig'] );
		ksort( $r );
		return hash_hmac( 'sha256', 'wp2ss-fix|' . wp_json_encode( $r ), wp_salt( 'auth' ) );
	}

	/** All valid records (unsigned or tampered ones are dropped). */
	public static function records() {
		$all = get_site_option( self::OPTION, array() );
		$out = array();
		foreach ( is_array( $all ) ? $all : array() as $id => $r ) {
			if ( is_array( $r ) && ! empty( $r['sig'] ) && hash_equals( self::sign( $r ), (string) $r['sig'] ) ) {
				$out[ $id ] = $r;
			}
		}
		return $out;
	}

	private static function save_record( $r ) {
		$all              = get_site_option( self::OPTION, array() );
		$all              = is_array( $all ) ? $all : array();
		$r['sig']         = self::sign( $r );
		$all[ $r['id'] ]  = $r;
		update_site_option( self::OPTION, $all );
	}

	private static function drop_record( $id ) {
		$all = get_site_option( self::OPTION, array() );
		if ( is_array( $all ) ) {
			unset( $all[ $id ] );
			update_site_option( self::OPTION, $all );
		}
	}

	/** Fix record for a finding (so the UI can show "Quarantined — Undo"). */
	public static function record_for_finding( $finding_id ) {
		foreach ( self::records() as $r ) {
			if ( isset( $r['finding'] ) && $r['finding'] === $finding_id && 'done' === $r['state'] ) {
				return $r;
			}
		}
		return null;
	}

	/* ------------------------------------------------------------------ */
	/* Apply / undo                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Apply the fix offered for a finding from the last report.
	 *
	 * @return array|WP_Error The fix record.
	 */
	public static function apply( $finding_id, $user_id = 0 ) {
		$finding = null;
		$report  = WP2SS_Scanner::last_report();
		foreach ( $report ? $report['findings'] : array() as $f ) {
			if ( $f['id'] === $finding_id ) {
				$finding = $f;
			}
		}
		if ( ! $finding ) {
			return new WP_Error( 'wp2ss_no_finding', __( 'That finding isn’t in the latest report. Scan again and retry.', 'wp2shell-scanner' ) );
		}
		if ( self::record_for_finding( $finding_id ) ) {
			return new WP_Error( 'wp2ss_done', __( 'This has already been fixed.', 'wp2shell-scanner' ) );
		}
		$fix = self::fix_for( $finding );
		if ( ! $fix ) {
			return new WP_Error( 'wp2ss_no_fix', __( 'There’s no automatic fix for this finding.', 'wp2shell-scanner' ) );
		}

		$r = array(
			'id'      => strtolower( wp_generate_password( 12, false ) ),
			'finding' => $finding_id,
			'action'  => $fix['action'],
			'message' => $finding['message'],
			'by'      => (int) $user_id,
			'at'      => time(),
			'state'   => 'done',
		);

		if ( 'demote' === $fix['action'] ) {
			$res = self::demote( (int) $fix['target'] );
			if ( is_wp_error( $res ) ) {
				return $res;
			}
			$r += $res;
		} else {
			if ( 'quarantine_plugin' === $fix['action'] ) {
				self::deactivate_folder( $fix['target'] );
			}
			$res = self::quarantine( $fix['target'] );
			if ( is_wp_error( $res ) ) {
				return $res;
			}
			$r += $res;
		}

		self::save_record( $r );
		/**
		 * Fires after a one-click fix.
		 *
		 * @param array $record The fix record.
		 */
		do_action( 'wp2ss_fix_applied', $r );
		return $r;
	}

	/** Undo a fix. */
	public static function undo( $id ) {
		$all = self::records();
		if ( empty( $all[ $id ] ) ) {
			return new WP_Error( 'wp2ss_no_record', __( 'Fix not found.', 'wp2shell-scanner' ) );
		}
		$r = $all[ $id ];
		if ( 'demote' === $r['action'] ) {
			$res = self::undemote( $r );
		} else {
			$res = self::restore( $r );
		}
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		self::drop_record( $id );
		do_action( 'wp2ss_fix_undone', $r );
		return true;
	}

	/** Permanently delete a quarantined item. */
	public static function purge( $id ) {
		$all = self::records();
		if ( empty( $all[ $id ] ) || 'demote' === $all[ $id ]['action'] ) {
			return new WP_Error( 'wp2ss_no_record', __( 'Quarantined item not found.', 'wp2shell-scanner' ) );
		}
		$q = $all[ $id ]['quarantined'];
		if ( ! self::in_qdir( $q ) ) {
			return new WP_Error( 'wp2ss_bad_path', __( 'Refusing to delete something outside the quarantine folder.', 'wp2shell-scanner' ) );
		}
		self::rrmdir( $q );
		self::drop_record( $id );
		return true;
	}

	/* ------------------------------------------------------------------ */

	private static function in_qdir( $path ) {
		$q = self::qdir();
		return $q && 0 === strpos( wp_normalize_path( $path ) . '/', $q . '/' ) && wp_normalize_path( $path ) !== $q;
	}

	private static function quarantine( $target ) {
		if ( ! self::safe_target( $target ) ) {
			return new WP_Error( 'wp2ss_unsafe', __( 'That location can’t be quarantined safely.', 'wp2shell-scanner' ) );
		}
		$q = self::qdir( true );
		if ( ! $q || ! is_writable( $q ) ) {
			return new WP_Error( 'wp2ss_no_qdir', __( 'Couldn’t create the quarantine folder in wp-content. Ask your host to make wp-content writable, or remove the file by hand.', 'wp2shell-scanner' ) );
		}
		$real = wp_normalize_path( realpath( $target ) );
		$sha1 = is_file( $real ) ? (string) @sha1_file( $real ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$dest = $q . '/' . gmdate( 'Ymd-His' ) . '-' . strtolower( wp_generate_password( 6, false ) ) . '-' . sanitize_file_name( basename( $real ) ) . '.quarantined';

		if ( ! @rename( $real, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			// Different filesystem, or a rename the host blocks: copy, then delete the original.
			if ( is_dir( $real ) || ! @copy( $real, $dest ) || ! @unlink( $real ) ) { // phpcs:ignore
				if ( file_exists( $dest ) && file_exists( $real ) ) {
					@unlink( $dest ); // phpcs:ignore
				}
				return new WP_Error( 'wp2ss_move_failed', __( 'PHP isn’t allowed to move this file (file permissions). Remove it with your host’s file manager instead.', 'wp2shell-scanner' ) );
			}
		}
		// Make sure nothing in a quarantined folder can execute, even if the folder is reachable.
		if ( is_dir( $dest ) ) {
			self::defang( $dest );
		}
		return array(
			'original'    => $real,
			'quarantined' => $dest,
			'kind'        => is_dir( $dest ) ? 'dir' : 'file',
			'sha1'        => $sha1,
		);
	}

	/** Rename every PHP-ish file in a quarantined folder so it can't run. */
	private static function defang( $dir ) {
		$sig = WP2SS_Scanner::signatures();
		$it  = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD );
		foreach ( $it as $f ) {
			if ( preg_match( $sig['php_ext'], $f->getFilename() ) ) {
				@rename( $f->getPathname(), $f->getPathname() . '.off' ); // phpcs:ignore
			}
		}
	}

	private static function undefang( $dir ) {
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD );
		foreach ( $it as $f ) {
			if ( '.off' === substr( $f->getFilename(), -4 ) ) {
				@rename( $f->getPathname(), substr( $f->getPathname(), 0, -4 ) ); // phpcs:ignore
			}
		}
	}

	private static function restore( $r ) {
		if ( ! self::in_qdir( $r['quarantined'] ) || ! file_exists( $r['quarantined'] ) ) {
			return new WP_Error( 'wp2ss_missing', __( 'The quarantined copy is missing.', 'wp2shell-scanner' ) );
		}
		if ( file_exists( $r['original'] ) ) {
			return new WP_Error( 'wp2ss_exists', __( 'Something already exists at the original location, so it wasn’t overwritten.', 'wp2shell-scanner' ) );
		}
		$parent = dirname( $r['original'] );
		if ( ! is_dir( $parent ) && ! wp_mkdir_p( $parent ) ) {
			return new WP_Error( 'wp2ss_parent', __( 'The original folder no longer exists and couldn’t be recreated.', 'wp2shell-scanner' ) );
		}
		if ( 'dir' === $r['kind'] ) {
			self::undefang( $r['quarantined'] );
		}
		if ( ! @rename( $r['quarantined'], $r['original'] ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return new WP_Error( 'wp2ss_move_failed', __( 'Couldn’t move it back (file permissions).', 'wp2shell-scanner' ) );
		}
		return true;
	}

	private static function deactivate_folder( $folder ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$slug = basename( $folder );
		foreach ( array_keys( get_plugins() ) as $file ) {
			if ( 0 === strpos( $file, $slug . '/' ) ) {
				deactivate_plugins( $file, true, is_multisite() );
			}
		}
	}

	private static function demote( $user_id ) {
		$u = get_userdata( $user_id );
		if ( ! $u ) {
			return new WP_Error( 'wp2ss_no_user', __( 'That account no longer exists.', 'wp2shell-scanner' ) );
		}
		if ( get_current_user_id() === $user_id ) {
			return new WP_Error( 'wp2ss_self', __( 'You can’t remove your own admin rights here.', 'wp2shell-scanner' ) );
		}
		$roles = array();
		$sites = is_multisite() ? get_blogs_of_user( $user_id, true ) : array( (object) array( 'userblog_id' => get_current_blog_id() ) );
		foreach ( $sites as $site ) {
			$blog = (int) $site->userblog_id;
			if ( is_multisite() ) {
				switch_to_blog( $blog );
			}
			$su = new WP_User( $user_id );
			if ( in_array( 'administrator', (array) $su->roles, true ) ) {
				$roles[ $blog ] = array_values( (array) $su->roles );
				$su->set_role( 'subscriber' );
			}
			if ( is_multisite() ) {
				restore_current_blog();
			}
		}
		$super = false;
		if ( is_multisite() && is_super_admin( $user_id ) ) {
			require_once ABSPATH . 'wp-admin/includes/ms.php';
			$super = revoke_super_admin( $user_id );
		}
		// Log them out everywhere.
		WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		return array(
			'user'  => $user_id,
			'login' => $u->user_login,
			'roles' => $roles,
			'super' => (bool) $super,
		);
	}

	private static function undemote( $r ) {
		if ( ! get_userdata( (int) $r['user'] ) ) {
			return new WP_Error( 'wp2ss_no_user', __( 'That account no longer exists.', 'wp2shell-scanner' ) );
		}
		foreach ( (array) $r['roles'] as $blog => $roles ) {
			if ( is_multisite() ) {
				switch_to_blog( (int) $blog );
			}
			$u = new WP_User( (int) $r['user'] );
			$u->set_role( '' );
			foreach ( (array) $roles as $role ) {
				$u->add_role( $role );
			}
			if ( is_multisite() ) {
				restore_current_blog();
			}
		}
		if ( ! empty( $r['super'] ) ) {
			require_once ABSPATH . 'wp-admin/includes/ms.php';
			grant_super_admin( (int) $r['user'] );
		}
		return true;
	}

	private static function rrmdir( $path ) {
		if ( is_dir( $path ) && ! is_link( $path ) ) {
			foreach ( (array) scandir( $path ) as $e ) {
				if ( '.' !== $e && '..' !== $e ) {
					self::rrmdir( $path . '/' . $e );
				}
			}
			@rmdir( $path ); // phpcs:ignore
		} else {
			@unlink( $path ); // phpcs:ignore
		}
	}
}
