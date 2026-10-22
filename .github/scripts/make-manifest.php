<?php
/**
 * Write manifest.json (SHA-256 of every file) into an unpacked release folder.
 * The plugin uses it to detect tampering with its own files.
 *
 *   php .github/scripts/make-manifest.php <plugin-folder> <version>
 */

$dir     = rtrim( $argv[1], '/' );
$version = $argv[2];
$files   = array();
$it      = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
foreach ( $it as $f ) {
	$rel = ltrim( substr( str_replace( '\\', '/', $f->getPathname() ), strlen( $dir ) ), '/' );
	if ( 'manifest.json' !== $rel ) {
		$files[ $rel ] = hash_file( 'sha256', $f->getPathname() );
	}
}
ksort( $files );
file_put_contents( "$dir/manifest.json", json_encode( array( 'version' => $version, 'files' => $files ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );
fwrite( STDERR, count( $files ) . " files hashed\n" );
