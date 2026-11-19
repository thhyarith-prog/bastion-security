<?php
/**
 * Firewall rule set.
 *
 * Each rule:
 *   cat     Category (sqli, xss, lfi, rce, objinj, ssrf, crlf).
 *   targets Request parts to inspect: get, post, json, cookie, uri, ua, key.
 *   on      Which normalised form to match: n = decoded + lower-case, s = n with SQL comments stripped.
 *   re      PCRE pattern.
 *
 * Patterns are written against decoded, lower-cased input, so they are tuned for low false
 * positives: each one needs syntax that only appears in an attack, not just a keyword.
 *
 * @package Bastion_Security
 */

return array(

	/* ---------------------------------------------------------------- SQL injection */
	'sqli-union'      => array(
		'cat'     => 'sqli',
		'desc'    => 'SQL injection: UNION SELECT',
		'targets' => array( 'get', 'post', 'json', 'cookie', 'uri' ),
		'on'      => 's',
		're'      => '~\bunion\b\s*(?:all\s+|distinct\s+)?\(?\s*select\b~',
	),
	'sqli-tautology'  => array(
		'cat'     => 'sqli',
		'desc'    => 'SQL injection: boolean tautology (\' OR 1=1)',
		'targets' => array( 'get', 'post', 'json', 'cookie' ),
		'on'      => 's',
		're'      => '~[\'"`)]\s*(?:or|and|xor|\|\||&&)\s+([\'"]?)(\w{1,20})\1\s*(?:=|like)\s*\1\2\b|[\'"`]\s*(?:or|and)\s+(?:true|false|not)\b\s*(?:--|#|;|$)~',
	),
	'sqli-time'       => array(
		'cat'     => 'sqli',
		'desc'    => 'SQL injection: time-based blind (SLEEP/BENCHMARK)',
		'targets' => array( 'get', 'post', 'json', 'cookie', 'uri' ),
		'on'      => 's',
		're'      => '~\b(?:sleep|pg_sleep)\s*\(\s*\d+(?:\.\d+)?\s*\)|\bbenchmark\s*\(\s*\d+\s*,|\bwaitfor\s+delay\s+[\'"]~',
	),
	'sqli-schema'     => array(
		'cat'     => 'sqli',
		'desc'    => 'SQL injection: schema / user table enumeration',
		'targets' => array( 'get', 'post', 'json', 'cookie' ),
		'on'      => 's',
		're'      => '~\bselect\b.{1,200}?\bfrom\b.{0,60}?\b(?:information_schema|mysql\.user|sqlite_master|pg_shadow|\w+_users\b)~s',
	),
	'sqli-stacked'    => array(
		'cat'     => 'sqli',
		'desc'    => 'SQL injection: stacked destructive query',
		'targets' => array( 'get', 'post', 'json', 'cookie' ),
		'on'      => 's',
		're'      => '~;\s*(?:drop|truncate|alter)\s+(?:table|database)\b|;\s*(?:insert\s+into|delete\s+from|update)\s+[`\w]+\s*(?:\(|set\b|where\b|values\b)~',
	),
	'sqli-file'       => array(
		'cat'     => 'sqli',
		'desc'    => 'SQL injection: file read/write (LOAD_FILE / INTO OUTFILE)',
		'targets' => array( 'get', 'post', 'json', 'cookie', 'uri' ),
		'on'      => 's',
		're'      => '~\bload_file\s*\(|\binto\s+(?:out|dump)file\b~',
	),
	'sqli-error'      => array(
		'cat'     => 'sqli',
		'desc'    => 'SQL injection: error-based extraction',
		'targets' => array( 'get', 'post', 'json', 'cookie', 'uri' ),
		'on'      => 's',
		're'      => '~\b(?:extractvalue|updatexml)\s*\(|\bfloor\s*\(\s*rand\s*\(|@@(?:version|datadir|hostname|basedir)\b|\b(?:group_)?concat(?:_ws)?\s*\(.{0,60}?(?:0x[0-9a-f]{6,}|database\s*\(\s*\)|user\s*\(\s*\))~s',
	),

	/* ----------------------------------------------------------------- Cross-site scripting */
	'xss-script'      => array(
		'cat'     => 'xss',
		'desc'    => 'XSS: <script> tag',
		'targets' => array( 'get', 'post', 'json', 'uri' ),
		'on'      => 'n',
		're'      => '~<\s*/?\s*script\b~',
	),
	'xss-handler'     => array(
		'cat'     => 'xss',
		'desc'    => 'XSS: inline event handler inside a tag',
		'targets' => array( 'get', 'post', 'json', 'uri' ),
		'on'      => 'n',
		're'      => '~<[a-z!/][^>]*?[\s/"\']on[a-z]{3,25}\s*=~',
	),
	'xss-uri'         => array(
		'cat'     => 'xss',
		'desc'    => 'XSS: javascript:/vbscript: URI',
		'targets' => array( 'get', 'post', 'json', 'uri' ),
		'on'      => 'n',
		're'      => '~(?:^|[\s\'"=(<`])(?:javascript|vbscript|livescript)\s*:(?!\s)|\bdata\s*:\s*text/html\b~',
	),
	'xss-tags'        => array(
		'cat'     => 'xss',
		'desc'    => 'XSS: dangerous HTML element',
		'targets' => array( 'get', 'post', 'json', 'uri' ),
		'on'      => 'n',
		're'      => '~<\s*(?:iframe|frame|object|embed|applet|meta|base|svg|math|isindex|xss|template)\b~',
	),
	'xss-dom'         => array(
		'cat'     => 'xss',
		'desc'    => 'XSS: DOM sink / cookie theft',
		'targets' => array( 'get', 'post', 'json', 'uri' ),
		'on'      => 'n',
		're'      => '~\bdocument\s*\.\s*(?:cookie|domain|write)\b|\.innerhtml\s*=|\bstring\.fromcharcode\s*\(|\balert\s*\(\s*(?:document|1|\'xss)|\bnew\s+function\s*\(~',
	),

	/* ---------------------------------------------------------- Traversal / file inclusion */
	'lfi-traversal'   => array(
		'cat'     => 'lfi',
		'desc'    => 'Path traversal',
		'targets' => array( 'get', 'post', 'json', 'cookie', 'uri' ),
		'on'      => 'n',
		're'      => '~(?:\.\.[/\\\\]){2,}|\.\.[/\\\\].{0,80}?(?:wp-config|\.env\b|\.htaccess|etc/passwd)~',
	),
	'lfi-sensitive'   => array(
		'cat'     => 'lfi',
		'desc'    => 'Local file inclusion: system file',
		'targets' => array( 'get', 'post', 'json', 'cookie', 'uri' ),
		'on'      => 'n',
		're'      => '~/etc/(?:passwd|shadow|group|hosts)\b|/proc/self/(?:environ|fd|cmdline)|c:[/\\\\]+windows[/\\\\]+win\.ini|\bboot\.ini\b~',
	),
	'lfi-wrapper'     => array(
		'cat'     => 'lfi',
		'desc'    => 'File inclusion: PHP stream wrapper',
		'targets' => array( 'get', 'post', 'json', 'cookie' ),
		'on'      => 'n',
		're'      => '~\b(?:php|phar|zip|expect|glob|compress\.zlib|data)://~',
	),
	'lfi-wpconfig'    => array(
		'cat'     => 'lfi',
		'desc'    => 'Attempt to read wp-config.php',
		'targets' => array( 'get', 'post', 'json', 'cookie' ),
		'on'      => 'n',
		're'      => '~\bwp-config\.php\b~',
	),

	/* --------------------------------------------------------------- Remote code execution */
	'rce-phptag'      => array(
		'cat'     => 'rce',
		'desc'    => 'PHP code injection: <?php tag',
		'targets' => array( 'get', 'post', 'json', 'cookie', 'ua' ),
		'on'      => 'n',
		're'      => '~<\?(?:php\b|=)~',
	),
	'rce-phpfunc'     => array(
		'cat'     => 'rce',
		'desc'    => 'PHP code injection: dangerous function call',
		'targets' => array( 'get', 'post', 'json', 'cookie', 'ua' ),
		'on'      => 'n',
		're'      => '~\b(?:shell_exec|passthru|proc_open|pcntl_exec|popen|system|exec|assert|eval|call_user_func|create_function)\s*\(\s*(?:\$_|base64_decode|str_rot13|gzinflate|hex2bin|[\'"]\s*(?:id|whoami|uname|ls|cat|wget|curl|bash|sh)\b)~',
	),
	'rce-shell'       => array(
		'cat'     => 'rce',
		'desc'    => 'OS command injection',
		'targets' => array( 'get', 'post', 'json', 'cookie', 'ua' ),
		'on'      => 'n',
		're'      => '~(?:^|[;|`\n]|\$\(|&&)\s*(?:(?:wget|curl)\s+(?:-[a-z]+\s+)*https?://|(?:ba|z|k)?sh\s+-[ci]\b|nc(?:at)?\s+-[elvp]\b|cat\s+/etc/|uname\s+-a\b|rm\s+-rf\s+/|chmod\s+[0-7]{3,4}\s|/bin/(?:ba)?sh\b|python[23]?\s+-c\b|perl\s+-e\b|php\s+-r\b)|(?:[;|`]|\$\(|&&)\s*(?:whoami|id|ifconfig|uname)\s*(?:$|[;|`)&#])~m',
	),
	'rce-log4shell'   => array(
		'cat'     => 'rce',
		'desc'    => 'JNDI / Log4Shell lookup',
		'targets' => array( 'get', 'post', 'json', 'cookie', 'uri', 'ua' ),
		'on'      => 'n',
		're'      => '~\$\{[^}]{0,30}(?:jndi|lower:|upper:|::-j|env:)~',
	),
	'objinj'          => array(
		'cat'     => 'objinj',
		'desc'    => 'PHP object injection (serialized object)',
		'targets' => array( 'get', 'post', 'json', 'cookie' ),
		'on'      => 'n',
		're'      => '~(?:^|[;{\s])[oc]:\+?\d+:"[a-z_\\\\][a-z0-9_\\\\]*":\+?\d+:\{~',
	),

	/* ------------------------------------------------------------------- SSRF / CRLF */
	'ssrf-metadata'   => array(
		'cat'     => 'ssrf',
		'desc'    => 'SSRF: cloud metadata / loopback URL',
		'targets' => array( 'get', 'post', 'json' ),
		'on'      => 'n',
		're'      => '~\b(?:https?|gopher|dict|ftp)://(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|\[?::1\]?|127\.\d+\.\d+\.\d+|0\.0\.0\.0|localhost)(?:[:/]|$)~',
	),
	'crlf'            => array(
		'cat'     => 'crlf',
		'desc'    => 'HTTP header injection (CRLF)',
		'targets' => array( 'get', 'uri' ),
		'on'      => 'n',
		're'      => '~[\r\n]\s*(?:set-cookie|location|content-type|content-length)\s*:~',
	),
);
