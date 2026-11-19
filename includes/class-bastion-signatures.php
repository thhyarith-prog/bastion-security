<?php
/**
 * Malware signatures for the file scanner.
 *
 * Literal markers are written with a character class (e.g. File[s]Man) so this file never
 * matches its own patterns, without having to exclude Bastion's folder from scans.
 *
 * Signatures target obfuscation and backdoor *behaviour* (decoding chains fed into eval,
 * request data used as code, known shell markers) rather than single function names, which
 * keeps false positives on legitimate plugins low. Every hit shows the matching line so it
 * can be reviewed before acting.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Signatures {

	/**
	 * @return array id => [sev, desc, re, scope (php|js|htaccess|any), optional second regex that must also match]
	 */
	public static function all() {
		$input = '\$_(?:GET|POST|REQUEST|COOKIE|SERVER\s*\[\s*[\'"]HTTP_)';
		return array(
			'php-eval-decode'      => array( 4, 'eval() of decoded/obfuscated data', '~\b(?:eval|assert)\s*\(\s*(?:@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|convert_uudecode|hex2bin|rawurldecode|urldecode)\s*\()~i', 'php' ),
			'php-eval-input'       => array( 4, 'Request data executed as PHP code', '~\b(?:eval|assert|create_function)\s*\(\s*(?:stripslashes\s*\(\s*)?@?' . $input . '~i', 'php' ),
			'php-input-call'       => array( 4, 'Request data called as a function', '~' . $input . '\s*\[[^\]]{1,40}\]\s*\(~i', 'php' ),
			'php-shell-input'      => array( 4, 'Shell command built from request data', '~\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:stripslashes\s*\(\s*)?@?' . $input . '~i', 'php' ),
			'php-include-input'    => array( 4, 'File included from request data', '~\b(?:include|require)(?:_once)?\s*\(?\s*@?' . $input . '~i', 'php' ),
			'php-preg-e'           => array( 4, 'preg_replace /e code execution', '~preg_replace\s*\(\s*([\'"])([^\w\s\\\\]).{0,200}?\2[imsxuADSUXJ]*e[imsxuADSUXJ]*\1~', 'php' ),
			'php-shell-marker'     => array( 4, 'Known web shell', '~(?:File[s]Man|WSOsetcooki[e]|wso_versio[n]|c99shel[l]|c99_buf[f]|r57shel[l]|b37[4]k|IndoXploi[t]|AnonymousFo[x]|0byt3m1n[1]|Alfa_Tea[m]|ALFA_SHEL[L]|Mr\.?Combe[t]|uname\s*-a.{0,80}Safe_?Mode|Sh3l[l]|BlackHat\s+Shell|marijuana\s*shell|Priv8\s*Shell)~i', 'any' ),
			'php-globals-obf'      => array( 3, 'Obfuscated $GLOBALS / variable-variable code', '~\$\{\s*[\'"]\\\\x47\\\\x4c|\$GLOBALS\s*\[\s*[\'"][^\'"]{1,30}[\'"]\s*\]\s*\[\s*\d+\s*\]\s*\(|\$\{\s*\$\{|\$\{"\\\\x~i', 'php' ),
			'php-chr-chain'        => array( 3, 'Code assembled from chr() calls', '~(?:chr\s*\(\s*\d{2,3}\s*\)\s*\.\s*){10,}~i', 'php' ),
			'php-include-media'    => array( 3, 'PHP include of an image/icon/text file', '~\b(?:include|require)(?:_once)?\s*\(?\s*[\'"][^\'"\n]{1,200}\.(?:ico|png|jpe?g|gif|txt|bmp|css)[\'"]~i', 'php' ),
			'php-include-hex'      => array( 3, 'Include of an escaped (hidden) path', '~@?\b(?:include|require)(?:_once)?\s*\(?\s*["\'](?:\\\\(?:x[0-9a-f]{2}|[0-7]{3})){4,}~i', 'php' ),
			'php-write-input'      => array( 3, 'File written from request data', '~\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,120}' . $input . '~i', 'php' ),
			'php-b64-input'        => array( 3, 'Decoding request data', '~\b(?:base64_decode|gzinflate|str_rot13)\s*\(\s*@?' . $input . '~i', 'php' ),
			'php-auth-bypass'      => array( 2, 'Login cookie set from a request parameter', '~' . $input . '[^;]{0,300}?\bwp_set_auth_cookie\s*\(|\bwp_set_auth_cookie\s*\(\s*' . $input . '~is', 'php' ),
			'php-create-admin'     => array( 2, 'Code that creates an administrator account', '~\bwp_(?:create|insert)_user\b.{0,500}?[\'"]administrator[\'"]~is', 'php' ),
			'php-hide-user'        => array( 2, 'Code hiding users from the admin list', '~pre_user_query.{0,400}?user_login\s*!=|views_users.{0,300}?(?:unset|count)\s*\(~is', 'php' ),
			'php-remote-exec'      => array( 3, 'Remote code downloaded and executed', '~\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:file_get_contents|wp_remote_retrieve_body|curl_exec)\s*\(~i', 'php' ),
			'php-goto-obf'         => array( 2, 'Heavily obfuscated code (goto spaghetti)', '~(?:\bgoto\s+\w+;\s*(?:\w+:\s*)?){40,}~', 'php' ),
			'php-hex-obf'          => array( 2, 'Heavily hex-escaped strings', '~(?:\\\\x[0-9a-f]{2}){60,}~i', 'php' ),
			'php-long-encoded'     => array( 2, 'Large encoded payload with a decoder', '~[\'"][A-Za-z0-9+/=]{3000,}[\'"]~', 'php', '~\b(?:eval|assert|create_function|base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(~i' ),

			'js-packer'            => array( 2, 'Packed JavaScript (p,a,c,k,e,r packer)', '~eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[rd]\s*\)~', 'js' ),
			'js-fromcharcode'      => array( 3, 'Script built from a long character-code list', '~String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){40,}~', 'js' ),
			'js-unescape-write'    => array( 3, 'Hidden script injected with document.write + unescape', '~document\.write\s*\(\s*(?:unescape|atob|decodeURIComponent)\s*\(~i', 'js' ),
			'js-eval-atob'         => array( 3, 'Script decodes and runs a hidden payload (eval + atob)', '~\beval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(~i', 'js' ),
			'js-injected-loader'   => array( 3, 'Injected remote script loader', '~createElement\s*\(\s*[\'"]script[\'"]\s*\).{0,300}?\.src\s*=\s*(?:atob|String\.fromCharCode|[\'"]https?://[^\'"]*\.(?:tk|top|xyz|ru|cn|ga|ml|cf|gq)/)~is', 'js' ),
			'js-crypto-miner'      => array( 4, 'Cryptocurrency miner', '~\b(?:coinhiv[e]|CoinHiv[e]\.Anonymous|cryptonigh[t]|deepMine[r]|webmine\.pro|coin-hive\.com|crypto-loo[t])\b~i', 'any' ),

			'ht-prepend'           => array( 3, 'auto_prepend_file / auto_append_file set by a foreign file', '~^\s*(?:php_value\s+)?auto_(?:prepend|append)_file\s*=?\s*(?!.*bastion-waf-prepend)~mi', 'htaccess' ),
			'ht-seo-redirect'      => array( 3, 'Search-engine-referrer redirect (SEO spam)', '~RewriteCond\s+%\{HTTP_(?:REFERER|USER_AGENT)\}[^\n]*(?:google|bing|yahoo|baidu|yandex)[\s\S]{0,300}?RewriteRule[^\n]*https?://~i', 'htaccess' ),
			'ht-handler'           => array( 3, 'Images or text configured to run as PHP', '~(?:AddHandler|AddType|SetHandler)[^\n]*(?:php|x-httpd)[^\n]*\.(?:jpe?g|png|gif|ico|txt|css)~i', 'htaccess' ),
		);
	}

	/**
	 * @param string $content File contents.
	 * @param string $scope   php | js | htaccess.
	 * @return array[] [id, sev, desc, line, snippet]
	 */
	public static function scan( $content, $scope ) {
		$hits = array();
		foreach ( self::all() as $id => $sig ) {
			list( $sev, $desc, $re, $sig_scope ) = $sig;
			if ( 'any' !== $sig_scope && $sig_scope !== $scope ) {
				continue;
			}
			if ( isset( $sig[4] ) && ! preg_match( $sig[4], $content ) ) {
				continue; // Secondary condition (e.g. a decoder must also be present).
			}
			if ( @preg_match( $re, $content, $m, PREG_OFFSET_CAPTURE ) ) {
				$offset = $m[0][1];
				$line   = substr_count( $content, "\n", 0, $offset ) + 1;
				$hits[] = array(
					'id'      => $id,
					'sev'     => $sev,
					'desc'    => $desc,
					'line'    => $line,
					'snippet' => self::snippet( $m[0][0] ),
				);
			}
		}
		return $hits;
	}

	private static function snippet( $s ) {
		$s = preg_replace( '/\s+/', ' ', (string) $s );
		if ( function_exists( 'mb_substr' ) ) {
			$s = mb_substr( $s, 0, 160, 'UTF-8' );
		} else {
			$s = substr( $s, 0, 160 );
		}
		return wp_check_invalid_utf8( $s, true );
	}
}
