<?php
/**
 * Run the scanner's code signatures over legitimate code (WordPress core and
 * popular plugins) and fail if anything above "medium" matches.
 *
 *   php tests/false-positives.php <dir> [<dir>…]
 *
 * "Medium" hits are listed for review but allowed: that tier exists for
 * patterns some legitimate plugins share.
 */

define( 'ABSPATH', __DIR__ . '/' );
function apply_filters( $hook, $value ) { return $value; }
require dirname( __DIR__ ) . '/includes/class-scanner.php';

$sig    = WP2SS_Scanner::signatures();
$files  = 0;
$fail   = 0;
$medium = 0;
foreach ( array_slice( $argv, 1 ) as $root ) {
	$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD );
	foreach ( $it as $f ) {
		if ( ! preg_match( $sig['php_ext'], $f->getFilename() ) || $f->getSize() > WP2SS_Scanner::MAX_READ ) {
			continue;
		}
		$files++;
		$hit = WP2SS_Scanner::match_code( (string) file_get_contents( $f->getPathname() ) );
		if ( ! $hit ) {
			continue;
		}
		$serious = WP2SS_Scanner::sev_rank( $hit[0] ) >= 4;
		$serious ? $fail++ : $medium++;
		printf( "%s %-8s %s :: %s\n", $serious ? 'FAIL' : 'note', $hit[0], $hit[1], $f->getPathname() );
	}
}
printf( "\n%d PHP files checked: %d high/critical false positives, %d medium notes.\n", $files, $fail, $medium );
exit( $fail ? 1 : 0 );
