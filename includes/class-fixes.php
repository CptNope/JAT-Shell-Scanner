<?php
/**
 * One-click fixes, every one of them reversible.
 *
 * Scans never change anything. Fixes run only when an administrator clicks
 * one (or runs `wp php2shell fix`), and each can be undone:
 *
 *  - Quarantine: a flagged file or plugin folder is moved into a private,
 *    randomly named folder in this plugin's folder in uploads
 *    (uploads/jat-shell-scanner/), which is blocked from the web, and
 *    renamed so it can't run.
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
	const DIR_OPTION = 'wp2ss_quarantine_folder';
	/** Builds before 1.6 kept quarantine in wp-content; those records can still be restored or deleted. */
	const LEGACY_DIR_OPTION = 'wp2ss_quarantine_dir';

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
					'label'   => __( 'Remove admin rights', 'jat-shell-scanner' ),
					'target'  => $id,
					'confirm' => __( 'Turn this account into a Subscriber? It will lose all admin powers. You can undo this.', 'jat-shell-scanner' ),
				);
			}
			return null;
		}

		if ( ! self::files_allowed() || '' === $loc || '/' !== $loc[0] && ! preg_match( '#^[A-Za-z]:/#', $loc ) ) {
			return null;
		}

		// A whole plugin folder (wp2shell_<hex>, CMSmap, fake cache plugin, gg-…).
		if ( 'plugin' === $f['type'] ) {
			$plugin_dir = WP2SS_Paths::plugins();
			$path       = wp_normalize_path( $loc );
			if ( 0 === strpos( $path, $plugin_dir . '/' ) ) {
				$folder = $plugin_dir . '/' . strtok( substr( $path, strlen( $plugin_dir ) + 1 ), '/' );
				if ( self::safe_target( $folder ) ) {
					return array(
						'action'  => 'quarantine_plugin',
						'label'   => __( 'Quarantine plugin', 'jat-shell-scanner' ),
						'target'  => $folder,
						'confirm' => __( 'Deactivate this plugin and move it into quarantine, where it can’t run? You can restore it later.', 'jat-shell-scanner' ),
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
			if ( self::safe_target( $loc ) && @is_file( $loc ) && ! self::through_link( $loc ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return array(
					'action'  => 'quarantine',
					'label'   => __( 'Quarantine', 'jat-shell-scanner' ),
					'target'  => wp_normalize_path( $loc ),
					'confirm' => __( 'Move this into quarantine, where it can’t run? You can restore it later.', 'jat-shell-scanner' ),
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
		if ( self::through_link( $path ) ) {
			return false; // A link could point anywhere — and could be swapped in after the scan.
		}
		$real = realpath( $path );
		if ( ! $real || ! file_exists( $real ) ) {
			return false;
		}
		$real    = wp_normalize_path( $real );
		$abs     = WP2SS_Paths::real( WP2SS_Paths::core() );
		$content = WP2SS_Paths::real( WP2SS_Paths::content() );
		$plugins = WP2SS_Paths::real( WP2SS_Paths::plugins() );
		$inside  = 0 === strpos( $real . '/', $abs . '/' ) || 0 === strpos( $real . '/', $content . '/' );
		if ( ! $inside ) {
			$inside = $plugins && 0 === strpos( $real . '/', $plugins . '/' );
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
			$abs . '/wp-login.php',
			$abs . '/wp-cron.php',
			$abs . '/xmlrpc.php',
			$abs . '/wp-activate.php',
			$abs . '/wp-signup.php',
			$abs . '/wp-comments-post.php',
			$abs . '/wp-links-opml.php',
			$abs . '/wp-mail.php',
			$abs . '/wp-trackback.php',
			$abs . '/.htaccess',
			$abs . '/.user.ini',
			$content . '/db.php',
			$content . '/object-cache.php',
			$content . '/advanced-cache.php',
			$content . '/sunrise.php',
			$content . '/plugins',
			$content . '/themes',
			$content . '/uploads',
			$content . '/mu-plugins',
			$plugins,
			WP2SS_Paths::real( WP2SS_Paths::themes() ),
			WP2SS_Paths::real( WP2SS_Paths::uploads() ),
			WP2SS_Paths::real( WP2SS_Paths::mu_plugins() ),
			WP2SS_Paths::real( WP2SS_DIR ),
			WP2SS_Paths::storage(),
			self::qdir(),
			self::legacy_qdir(),
		);
		if ( in_array( $real, $never, true ) ) {
			return false;
		}
		// Nothing inside this plugin's own folder except files it doesn't ship (an attacker's addition).
		$self = WP2SS_Paths::real( WP2SS_DIR );
		if ( 0 === strpos( $real . '/', $self . '/' ) && ( is_dir( $real ) || in_array( substr( $real, strlen( $self ) + 1 ), WP2SS_Scanner::OWN_PHP, true ) ) ) {
			return false;
		}
		// Whole theme folders are too big a hammer; single files inside them are fine.
		$themes = WP2SS_Paths::real( WP2SS_Paths::themes() );
		if ( is_dir( $real ) && dirname( $real ) === $themes ) {
			return false;
		}
		return true;
	}

	/**
	 * Does this path, or any folder between it and the site's own folders,
	 * go through a symbolic link? (The site folders themselves may be links;
	 * that's the host's business.)
	 */
	public static function through_link( $path ) {
		$p     = wp_normalize_path( (string) $path );
		$bases = array_filter(
			array_unique(
				array(
					WP2SS_Paths::core(),
					WP2SS_Paths::content(),
					WP2SS_Paths::plugins(),
					WP2SS_Paths::real( WP2SS_Paths::core() ),
					WP2SS_Paths::real( WP2SS_Paths::content() ),
					WP2SS_Paths::real( WP2SS_Paths::plugins() ),
				)
			)
		);
		$base = '';
		foreach ( $bases as $b ) {
			if ( 0 === strpos( $p, $b . '/' ) && strlen( $b ) > strlen( $base ) ) {
				$base = $b;
			}
		}
		if ( '' === $base ) {
			return true; // Outside the site: treat as unsafe.
		}
		while ( strlen( $p ) > strlen( $base ) ) {
			if ( @is_link( $p ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return true;
			}
			$p = dirname( $p );
		}
		return false;
	}

	/* ------------------------------------------------------------------ */
	/* Quarantine folder                                                   */
	/* ------------------------------------------------------------------ */

	/** The private quarantine folder in uploads/jat-shell-scanner (created on first use). */
	public static function qdir( $create = false ) {
		$name = get_site_option( self::DIR_OPTION );
		if ( ! $name || ! preg_match( '/^quarantine-[a-z0-9]{16}$/', $name ) ) {
			if ( ! $create ) {
				return '';
			}
			$name = 'quarantine-' . strtolower( wp_generate_password( 16, false ) );
			update_site_option( self::DIR_OPTION, $name );
		}
		$base = WP2SS_Paths::storage( $create );
		if ( '' === $base ) {
			return '';
		}
		$dir = $base . '/' . $name;
		if ( $create && ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return '';
		}
		if ( $create ) {
			WP2SS_Paths::protect( $dir );
		}
		return $dir;
	}

	/** The wp-content quarantine folder of builds before 1.6, if one exists ('' otherwise). Only read and emptied, never added to. */
	public static function legacy_qdir() {
		$name = get_site_option( self::LEGACY_DIR_OPTION );
		if ( ! $name || ! preg_match( '/^wp2ss-quarantine-[a-z0-9]{16}$/', $name ) ) {
			return '';
		}
		$dir = WP2SS_Paths::content() . '/' . $name;
		return is_dir( $dir ) ? $dir : '';
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
	public static function record_for_finding( $finding ) {
		$finding_id = is_array( $finding ) ? $finding['id'] : (string) $finding;
		$loc        = is_array( $finding ) && ! empty( $finding['location'] ) ? wp_normalize_path( (string) $finding['location'] ) : '';
		foreach ( self::records() as $r ) {
			// Other findings about the same file count as handled too.
			$same = $loc && 'demote' !== $r['action'] && ! empty( $r['original'] ) && ( wp_normalize_path( $r['original'] ) === $loc || 0 === strpos( $loc, wp_normalize_path( $r['original'] ) . '/' ) );
			if ( ( ( isset( $r['finding'] ) && $r['finding'] === $finding_id ) || $same ) && 'done' === $r['state'] ) {
				if ( 'demote' !== $r['action'] && ! empty( $r['original'] ) && file_exists( $r['original'] ) ) {
					continue; // Something is back at the quarantined path: it needs fixing again.
				}
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
			return new WP_Error( 'wp2ss_no_finding', __( 'That finding isn’t in the latest report. Scan again and retry.', 'jat-shell-scanner' ) );
		}
		if ( self::record_for_finding( $finding_id ) ) {
			return new WP_Error( 'wp2ss_done', __( 'This has already been fixed.', 'jat-shell-scanner' ) );
		}
		$fix = self::fix_for( $finding );
		if ( ! $fix ) {
			return new WP_Error( 'wp2ss_no_fix', __( 'There’s no automatic fix for this finding.', 'jat-shell-scanner' ) );
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
			// The file must still be the one the scan saw: never act on something swapped in since.
			if ( 'quarantine' === $fix['action'] && ! empty( $finding['sha1'] ) && ! hash_equals( (string) $finding['sha1'], (string) @sha1_file( $fix['target'] ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return new WP_Error( 'wp2ss_changed', __( 'This file has changed since the scan. Scan again, then retry.', 'jat-shell-scanner' ) );
			}
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
			return new WP_Error( 'wp2ss_no_record', __( 'Fix not found.', 'jat-shell-scanner' ) );
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
			return new WP_Error( 'wp2ss_no_record', __( 'Quarantined item not found.', 'jat-shell-scanner' ) );
		}
		$q = $all[ $id ]['quarantined'];
		if ( ! self::in_qdir( $q ) ) {
			return new WP_Error( 'wp2ss_bad_path', __( 'Refusing to delete something outside the quarantine folder.', 'jat-shell-scanner' ) );
		}
		self::rrmdir( $q );
		self::drop_record( $id );
		return true;
	}

	/* ------------------------------------------------------------------ */

	private static function in_qdir( $path ) {
		$path = wp_normalize_path( $path );
		foreach ( array( self::qdir(), self::legacy_qdir() ) as $q ) {
			if ( $q && 0 === strpos( $path . '/', $q . '/' ) && $path !== $q ) {
				return true;
			}
		}
		return false;
	}

	private static function quarantine( $target ) {
		if ( ! self::safe_target( $target ) ) {
			return new WP_Error( 'wp2ss_unsafe', __( 'That location can’t be quarantined safely.', 'jat-shell-scanner' ) );
		}
		$q = self::qdir( true );
		if ( ! $q || ! is_writable( $q ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Checks the plugin's own quarantine folder.
			return new WP_Error( 'wp2ss_no_qdir', __( 'Couldn’t create the quarantine folder in the uploads folder. Ask your host to make uploads writable, or remove the file by hand.', 'jat-shell-scanner' ) );
		}
		$real = wp_normalize_path( realpath( $target ) );
		$sha1 = is_file( $real ) ? (string) @sha1_file( $real ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors
		// No ".php" anywhere in the name: some servers run any file whose name merely contains it.
		$dest = $q . '/' . gmdate( 'Ymd-His' ) . '-' . strtolower( wp_generate_password( 6, false ) ) . '-' . str_replace( '.', '_', sanitize_file_name( basename( $real ) ) ) . '.quarantined';

		if ( ! @rename( $real, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.rename_rename -- Same-filesystem atomic move of a file already checked not to be a link; WP_Filesystem may need FTP credentials and isn't atomic.
			// Different filesystem, or a rename the host blocks: copy, then delete the original.
			if ( is_dir( $real ) || ! @copy( $real, $dest ) || ! @unlink( $real ) ) { // phpcs:ignore
				if ( file_exists( $dest ) && file_exists( $real ) ) {
					@unlink( $dest ); // phpcs:ignore
				}
				return new WP_Error( 'wp2ss_move_failed', __( 'PHP isn’t allowed to move this file (file permissions). Remove it with your host’s file manager instead.', 'jat-shell-scanner' ) );
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
			'defang'      => 2,
		);
	}

	/**
	 * Rename every file in a quarantined folder — .htaccess included — so
	 * nothing can run or change server rules: dots are encoded (so no ".php"
	 * is left anywhere in a name) and ".off" is appended. Reversible.
	 */
	private static function defang( $dir ) {
		foreach ( self::leaves( $dir ) as $path ) {
			$name = basename( $path );
			@rename( $path, dirname( $path ) . '/' . str_replace( array( '%', '.' ), array( '%25', '%2E' ), $name ) . '.off' ); // phpcs:ignore
		}
	}

	private static function undefang( $dir, $version ) {
		foreach ( self::leaves( $dir ) as $path ) {
			$name = basename( $path );
			if ( '.off' !== substr( $name, -4 ) ) {
				continue;
			}
			$orig = substr( $name, 0, -4 );
			if ( $version >= 2 ) {
				$orig = rawurldecode( $orig );
			}
			@rename( $path, dirname( $path ) . '/' . $orig ); // phpcs:ignore
		}
	}

	/** Files under a folder (not following links), collected first so renaming doesn't disturb the walk. */
	private static function leaves( $dir ) {
		$out = array();
		$it  = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD );
		foreach ( $it as $f ) {
			if ( ! $f->isDir() ) {
				$out[] = $f->getPathname();
			}
		}
		return $out;
	}

	private static function restore( $r ) {
		if ( ! self::in_qdir( $r['quarantined'] ) || ! file_exists( $r['quarantined'] ) ) {
			return new WP_Error( 'wp2ss_missing', __( 'The quarantined copy is missing.', 'jat-shell-scanner' ) );
		}
		if ( file_exists( $r['original'] ) ) {
			return new WP_Error( 'wp2ss_exists', __( 'Something already exists at the original location, so it wasn’t overwritten.', 'jat-shell-scanner' ) );
		}
		// The way back must still be the real folder it came from: no links swapped in since.
		$original = wp_normalize_path( $r['original'] );
		$parent   = dirname( $original );
		$exists   = $parent;
		while ( ! file_exists( $exists ) && dirname( $exists ) !== $exists ) {
			$exists = dirname( $exists );
		}
		if ( self::through_link( $original ) || wp_normalize_path( (string) realpath( $exists ) ) !== $exists ) {
			return new WP_Error( 'wp2ss_moved', __( 'The original folder has been replaced by a link since this was quarantined, so it wasn’t restored. Restore it by hand if you’re sure.', 'jat-shell-scanner' ) );
		}
		if ( ! is_dir( $parent ) && ! wp_mkdir_p( $parent ) ) {
			return new WP_Error( 'wp2ss_parent', __( 'The original folder no longer exists and couldn’t be recreated.', 'jat-shell-scanner' ) );
		}
		if ( 'dir' === $r['kind'] ) {
			self::undefang( $r['quarantined'], isset( $r['defang'] ) ? (int) $r['defang'] : 1 );
		}
		if ( ! @rename( $r['quarantined'], $r['original'] ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.rename_rename -- Same-filesystem atomic move of a file already checked not to be a link; WP_Filesystem may need FTP credentials and isn't atomic.
			return new WP_Error( 'wp2ss_move_failed', __( 'Couldn’t move it back (file permissions).', 'jat-shell-scanner' ) );
		}
		return true;
	}

	private static function deactivate_folder( $folder ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			WP2SS_Paths::admin_include( 'plugin.php' );
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
			return new WP_Error( 'wp2ss_no_user', __( 'That account no longer exists.', 'jat-shell-scanner' ) );
		}
		if ( get_current_user_id() === $user_id ) {
			return new WP_Error( 'wp2ss_self', __( 'You can’t remove your own admin rights here.', 'jat-shell-scanner' ) );
		}
		if ( ! is_multisite() && count( get_users( array( 'role' => 'administrator', 'fields' => 'ID', 'exclude' => array( $user_id ), 'number' => 1 ) ) ) < 1 ) {
			return new WP_Error( 'wp2ss_last_admin', __( 'This is the only administrator left, so its admin rights weren’t removed. Create your own administrator account first.', 'jat-shell-scanner' ) );
		}
		if ( is_multisite() && is_super_admin( $user_id ) && count( array_diff( get_super_admins(), array( $u->user_login ) ) ) < 1 ) {
			return new WP_Error( 'wp2ss_last_admin', __( 'This is the only network administrator left, so its rights weren’t removed.', 'jat-shell-scanner' ) );
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
			WP2SS_Paths::admin_include( 'ms.php' );
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
			return new WP_Error( 'wp2ss_no_user', __( 'That account no longer exists.', 'jat-shell-scanner' ) );
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
			WP2SS_Paths::admin_include( 'ms.php' );
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
