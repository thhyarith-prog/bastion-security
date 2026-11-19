<?php
/**
 * Bastion firewall engine.
 *
 * Runs in two phases:
 *  - early:    before WordPress (auto_prepend_file) or as the first mu-plugin. Cheap checks
 *              (IP blocks, countries, bots, probes, rate limits) and, for anonymous requests,
 *              the full rule set.
 *  - deferred: for requests carrying a login cookie, rule inspection waits until
 *              `plugins_loaded`, when the cookie can be verified. Administrators are then
 *              exempt and users with `unfiltered_html` skip XSS rules. This avoids the
 *              false positives that make other firewalls need a "learning mode" for admins.
 *
 * Standalone: must not depend on WordPress.
 *
 * @package Bastion_Security
 */

if ( class_exists( 'Bastion_Waf', false ) ) {
	return;
}

class Bastion_Waf {

	const BAD_UA = '~(?:sqlmap|nikto|wpscan|acunetix|nessus|masscan|zgrab|nmap\b|dirbuster|gobuster|feroxbuster|nuclei|jaeles|wfuzz|ffuf|hydra|havij|netsparker|w3af|openvas|whatweb|commix|xsstrike|fimap|arachni|morfeus|zmeu|appscan|bsqlbf|dotdotpwn|grabber|paros|webinspect|cgichk|teh forest lobster)~i';

	const PROBES = '~(?:/\.env(?:\.[\w.-]+)?$|/\.git(?:/|$)|/\.svn/|/\.hg/|/\.ds_store$|/\.aws/|/\.ssh/|/id_[rd]sa\b|/\.htpasswd$|/wp-config\.php[._\~-]?\w*\.(?:bak|old|orig|save|swp|txt|backup|dist|zip|tar|gz)$|/wp-config\.(?:bak|old|orig|txt|save)$|/wp-config\.php\~$|/[\w.-]*\.(?:sql|sql\.gz|sql\.zip|sql\.tar\.gz)$|/phpinfo\.php$|/(?:adminer|phpmyadmin|pma|myadmin)[\w.-]*\.php$|/vendor/phpunit/.*eval-stdin\.php|/wp-content/debug\.log$|/(?:shell|wso|c99|r57|alfa|cmd|b37[4]k|up|uploader|indoxploi[t]|wp-xmlrpc)\.php$|/server-status$|/\.well-known/[\w.-]+\.php$|/cgi-bin/)~i';

	const SKIP_KEYS = '~^(?:pwd|pass1|pass2|pass1-text|password|user_pass|new_password|confirm_password|current_password|post_password|_wpnonce|_wp_http_referer)$~i';

	const UPLOAD_EXT = '~\.(?:php\d?|phtml|phar|pht|phps|pl|py|cgi|asp|aspx|jsp|shtml|sh)(?:\.|$)|^\.ht|^\.user\.ini$~i';

	/** @var Bastion_Waf */
	private static $instance;

	/** @var array */
	public $config = array();

	/** @var Bastion_Waf_Storage */
	public $storage;

	/** @var string */
	public $ip = '';

	/** @var string */
	public $request_id = '';

	/** @var bool Rule inspection postponed until the login cookie can be verified. */
	public $deferred = false;

	/** @var bool */
	public $allowlisted = false;

	/** @var string|null */
	public $country;

	/** @var array|null */
	private $targets;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->storage    = new Bastion_Waf_Storage( BASTION_WAF_DIR );
		$this->config     = $this->storage->load_config();
		$this->ip         = Bastion_IP::detect( $_SERVER, $this->cfg( 'ip_mode', 'auto' ), (array) $this->cfg( 'trusted_proxies', array() ) );
		$this->request_id = bin2hex( random_bytes( 6 ) );
	}

	public function cfg( $key, $default = null ) {
		return array_key_exists( $key, $this->config ) ? $this->config[ $key ] : $default;
	}

	public function enabled() {
		return ! empty( $this->config['enabled'] );
	}

	/* ================================================================ phases */

	public function run_early() {
		if ( ! $this->enabled() || 'cli' === PHP_SAPI ) {
			return;
		}
		if ( Bastion_IP::in_list( $this->ip, (array) $this->cfg( 'allowlist', array() ) ) ) {
			$this->allowlisted = true;
			return;
		}

		$path = $this->path();

		// 1. Manual block list.
		if ( Bastion_IP::in_list( $this->ip, (array) $this->cfg( 'blocklist', array() ) ) ) {
			$this->deny( 'blocklist', 'IP address is on the block list', array( 'throttle_log' => true ) );
		}

		// 2. Temporary / automatic blocks.
		$block = $this->storage->get_block( $this->ip );
		if ( $block ) {
			if ( 'all' === $block['scope'] ) {
				$this->deny( 'ip_block', 'Blocked: ' . $block['reason'], array( 'throttle_log' => true ) );
			}
			if ( $this->is_login_attempt( $path ) ) {
				$this->deny( 'lockout', 'Locked out: ' . $block['reason'], array( 'throttle_log' => true, 'status' => 429 ) );
			}
		}

		// 3. Country blocking (only from headers set by trusted infrastructure).
		$countries = (array) $this->cfg( 'countries', array() );
		if ( $countries ) {
			$cc = $this->country();
			if ( $cc && in_array( $cc, $countries, true ) ) {
				if ( 'all' === $this->cfg( 'country_scope', 'login' ) || $this->is_login_page( $path ) ) {
					$this->deny( 'country', 'Access from country ' . $cc . ' is blocked', array( 'throttle_log' => true ) );
				}
			}
		}

		// 4. XML-RPC: fully disabled, or restricted (no multicall amplification, no pingbacks).
		//    system.multicall is registered by the XML-RPC server itself, not through a filter,
		//    so it has to be stopped here.
		if ( preg_match( '~/xmlrpc\.php$~i', $path ) ) {
			$xmlrpc = $this->cfg( 'xmlrpc_mode', 'restrict' );
			if ( 'disable' === $xmlrpc ) {
				$this->deny( 'xmlrpc', 'XML-RPC is disabled', array( 'throttle_log' => true ) );
			}
			if ( 'restrict' === $xmlrpc ) {
				$body = (string) @file_get_contents( 'php://input', false, null, 0, 1048576 );
				if ( preg_match( '~<methodName>\s*(system\.multicall|system\.listMethods|pingback\.ping|pingback\.extensions\.getPingbacks)\s*</methodName>~i', $body, $m ) && ! $this->only_learning( 'xmlrpc', 'XML-RPC method ' . $m[1], array( 'match' => $m[1] ) ) ) {
					$this->count_attack( 1 );
					$this->deny( 'xmlrpc', 'Blocked XML-RPC method ' . $m[1], array( 'match' => $m[1] ) );
				}
			}
		}

		// 5. Vulnerability scanners and attack tools.
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		if ( $this->cfg( 'block_bad_ua', true ) && '' !== $ua && preg_match( self::BAD_UA, $ua, $m ) && ! $this->only_learning( 'bad_bot', 'Attack tool user agent: ' . $m[0], array( 'match' => $m[0] ) ) ) {
			$this->count_attack( 2 );
			$this->deny( 'bad_bot', 'Attack tool user agent: ' . $m[0], array( 'match' => $m[0] ) );
		}

		// 6. Probes for secrets, backups and known web shells.
		if ( $this->cfg( 'block_probes', true ) && preg_match( self::PROBES, rawurldecode( $path ), $m ) && ! $this->only_learning( 'probe', 'Probe for sensitive file: ' . $m[0], array( 'match' => $m[0] ) ) ) {
			$this->count_attack( 2 );
			$this->deny( 'probe', 'Probe for sensitive file: ' . $m[0], array( 'match' => $m[0] ) );
		}

		// 7. Rate limiting.
		$rpm = (int) $this->cfg( 'rate_limit_rpm', 0 );
		if ( $rpm > 0 ) {
			$count = $this->storage->hit( 'req:' . $this->ip, 60 );
			if ( $count > $rpm && ! $this->only_learning( 'rate_limit', 'Rate limit exceeded: ' . $count . ' requests in one minute', array( 'throttle_log' => true ) ) ) {
				$secs = max( 60, (int) $this->cfg( 'rate_limit_seconds', 600 ) );
				$this->storage->add_block( $this->ip, $secs, 'Rate limit exceeded (' . $count . ' requests/minute)', 'all' );
				$this->deny( 'rate_limit', 'Rate limit exceeded: ' . $count . ' requests in one minute', array( 'status' => 429 ) );
			}
		}

		$has_cookie = $this->has_auth_cookie();

		// 8. User enumeration (?author=N, REST users endpoint) for anonymous visitors.
		if ( $this->cfg( 'block_user_enum', true ) && ! $has_cookie && empty( $_SERVER['HTTP_AUTHORIZATION'] ) && ! preg_match( '~/wp-admin/~', $path ) ) {
			$author = isset( $_GET['author'] ) ? $_GET['author'] : null;
			$route  = isset( $_GET['rest_route'] ) ? (string) $_GET['rest_route'] : '';
			if ( ( ( is_scalar( $author ) && preg_match( '/^\s*\d/', (string) $author ) )
				|| preg_match( '~/wp-json/wp/v2/users~i', $path )
				|| preg_match( '~^/?wp/v2/users~i', $route ) )
				&& ! $this->only_learning( 'user_enum', 'User enumeration', array( 'throttle_log' => true ) ) ) {
				$this->deny( 'user_enum', 'User enumeration blocked', array( 'throttle_log' => true ) );
			}
		}

		// 9. Attack signatures.
		if ( $has_cookie ) {
			$this->deferred = true; // Decide once the cookie is verified (see run_deferred).
			return;
		}
		$this->inspect( array() );
	}

	/**
	 * Called at plugins_loaded (earliest priority) once WordPress can validate the login cookie.
	 *
	 * @param int  $user_id         Verified user ID (0 = invalid/expired cookie).
	 * @param bool $is_admin        User can manage the site.
	 * @param bool $unfiltered_html User may post raw HTML.
	 */
	public function run_deferred( $user_id, $is_admin, $unfiltered_html ) {
		if ( ! $this->deferred ) {
			return;
		}
		$this->deferred = false;
		if ( $is_admin ) {
			return;
		}
		$this->inspect( $unfiltered_html ? array( 'xss' ) : array() );
	}

	/* ============================================================== inspection */

	private function inspect( array $skip_categories ) {
		$rules    = require __DIR__ . '/rules.php';
		$disabled = array_flip( (array) $this->cfg( 'disabled_rules', array() ) );
		$targets  = $this->targets();

		foreach ( $rules as $id => $rule ) {
			if ( isset( $disabled[ $id ] ) || in_array( $rule['cat'], $skip_categories, true ) ) {
				continue;
			}
			foreach ( $targets as $t ) {
				if ( ! in_array( $t['src'], $rule['targets'], true ) ) {
					continue;
				}
				$subject = 's' === $rule['on'] ? $t['s'] : $t['n'];
				if ( ! preg_match( $rule['re'], $subject, $m ) ) {
					continue;
				}
				// WordPress links back to itself (wp-login.php?redirect_to=http://localhost:8080/…)
				// on local and staging sites: a URL pointing at this very site is not SSRF.
				if ( 'ssrf' === $rule['cat'] && $this->only_points_to_self( $rule['re'], $subject ) ) {
					continue;
				}
				if ( $this->param_allowed( $id, $t['name'] ) ) {
					continue;
				}
				$ctx = array(
					'rule'  => $id,
					'cat'   => $rule['cat'],
					'param' => $t['src'] . ':' . $t['name'],
					'match' => $m[0],
				);
				if ( 'learning' === $this->cfg( 'mode', 'block' ) ) {
					$this->log( 'learning', $rule['desc'], $ctx );
					continue 2; // One log line per rule is enough.
				}
				$this->count_attack( 1 );
				$this->deny( 'waf', $rule['desc'], $ctx );
			}
		}

		if ( $this->cfg( 'block_php_uploads', true ) && ! empty( $_FILES ) ) {
			$this->inspect_uploads();
		}
	}

	/** True when every URL the rule matched in $subject has exactly this site's host and port. */
	private function only_points_to_self( $re, $subject ) {
		$host = isset( $_SERVER['HTTP_HOST'] ) ? strtolower( (string) $_SERVER['HTTP_HOST'] ) : '';
		if ( '' === $host || ! preg_match_all( '~(?:https?|gopher|dict|ftp)://[^\s"\'<>]+~i', $subject, $all ) ) {
			return false;
		}
		$found = false;
		foreach ( $all[0] as $url ) {
			if ( ! preg_match( $re, $url ) ) {
				continue; // Not one the rule cares about.
			}
			$found = true;
			$p     = parse_url( $url ); // phpcs:ignore -- runs before WordPress loads.
			if ( empty( $p['host'] ) || ! in_array( strtolower( $p['scheme'] ), array( 'http', 'https' ), true ) ) {
				return false;
			}
			$target = strtolower( $p['host'] ) . ( isset( $p['port'] ) ? ':' . (int) $p['port'] : '' );
			if ( $target !== $host ) {
				return false;
			}
		}
		return $found;
	}

	private function inspect_uploads() {
		foreach ( $this->flatten_files( $_FILES ) as $file ) {
			$reason = '';
			if ( preg_match( self::UPLOAD_EXT, $file['name'] ) ) {
				$reason = 'Executable file upload: ' . $file['name'];
			} elseif ( $file['tmp'] && is_uploaded_file( $file['tmp'] ) ) {
				$head = (string) @file_get_contents( $file['tmp'], false, null, 0, 262144 );
				if ( preg_match( '~<\?(?:php\b|=)~i', $head ) ) {
					$reason = 'PHP code hidden in upload: ' . $file['name'];
				}
			}
			if ( $reason ) {
				if ( 'learning' === $this->cfg( 'mode', 'block' ) ) {
					$this->log( 'learning', $reason, array( 'rule' => 'upload-php', 'cat' => 'upload' ) );
					continue;
				}
				$this->count_attack( 2 );
				$this->deny( 'waf', $reason, array( 'rule' => 'upload-php', 'cat' => 'upload', 'match' => $file['name'] ) );
			}
		}
	}

	private function flatten_files( $files ) {
		$out = array();
		foreach ( (array) $files as $f ) {
			if ( ! isset( $f['name'] ) ) {
				continue;
			}
			$names = (array) $f['name'];
			$tmps  = isset( $f['tmp_name'] ) ? (array) $f['tmp_name'] : array();
			array_walk_recursive(
				$names,
				function ( $name, $key ) use ( &$out, $tmps ) {
					$out[] = array(
						'name' => (string) $name,
						'tmp'  => isset( $tmps[ $key ] ) && is_string( $tmps[ $key ] ) ? $tmps[ $key ] : '',
					);
				}
			);
		}
		return $out;
	}

	private function targets() {
		if ( null !== $this->targets ) {
			return $this->targets;
		}
		$out = array();
		$this->flatten( 'get', $_GET, '', $out, 0 );
		$this->flatten( 'post', $_POST, '', $out, 0 );

		$ctype  = isset( $_SERVER['CONTENT_TYPE'] ) ? (string) $_SERVER['CONTENT_TYPE'] : '';
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET';
		if ( 'GET' !== $method && false !== stripos( $ctype, 'json' ) ) {
			$raw  = (string) @file_get_contents( 'php://input', false, null, 0, 2097152 );
			$json = json_decode( $raw, true );
			if ( is_array( $json ) ) {
				$this->flatten( 'json', $json, '', $out, 0 );
			}
		}

		$cookies = array();
		foreach ( $_COOKIE as $k => $v ) {
			if ( ! preg_match( '/^(?:wordpress_|wp-settings-|wp_lang|comment_author_|wp-postpass_|bastion_)/', (string) $k ) ) {
				$cookies[ $k ] = $v;
			}
		}
		$this->flatten( 'cookie', $cookies, '', $out, 0 );

		$out[] = $this->target( 'uri', 'path', rawurldecode( $this->path() ) );
		if ( ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$out[] = $this->target( 'ua', 'user-agent', (string) $_SERVER['HTTP_USER_AGENT'] );
		}
		$this->targets = $out;
		return $out;
	}

	private function flatten( $src, $data, $prefix, array &$out, $depth ) {
		if ( $depth > 10 || ! is_array( $data ) ) {
			return;
		}
		foreach ( $data as $k => $v ) {
			if ( count( $out ) > 3000 ) {
				return;
			}
			$k    = (string) $k;
			$name = '' === $prefix ? $k : $prefix . '[' . $k . ']';
			if ( preg_match( '/[^\w\-\[\]. ]/', $k ) ) {
				$out[] = $this->target( $src, 'key:' . $name, $k );
			}
			if ( is_array( $v ) ) {
				$this->flatten( $src, $v, $name, $out, $depth + 1 );
				continue;
			}
			if ( ! is_scalar( $v ) || preg_match( self::SKIP_KEYS, $k ) ) {
				continue;
			}
			$s = (string) $v;
			if ( '' === $s || ctype_alnum( $s ) ) {
				continue;
			}
			$out[] = $this->target( $src, $name, $s );
		}
	}

	private function target( $src, $name, $value ) {
		$n = self::normalize( substr( $value, 0, 65536 ) );
		return array(
			'src'  => $src,
			'name' => $name,
			'n'    => $n,
			's'    => self::sql_normalize( $n ),
		);
	}

	/** Undo layered URL/entity encoding so obfuscated payloads match plain-text rules. */
	public static function normalize( $v ) {
		$v = (string) $v;
		for ( $i = 0; $i < 3; $i++ ) {
			$d = rawurldecode( $v );
			if ( $d === $v ) {
				break;
			}
			$v = $d;
		}
		if ( false !== strpos( $v, '&' ) ) {
			$v = html_entity_decode( $v, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		}
		return strtolower( str_replace( "\0", '', $v ) );
	}

	/** Remove SQL comments (incl. MySQL versioned comments) that are used to split keywords. */
	public static function sql_normalize( $n ) {
		if ( false === strpos( $n, '/*' ) && false === strpos( $n, '#' ) && false === strpos( $n, '--' ) ) {
			return $n;
		}
		$n = preg_replace( '~/\*!\d*~', ' ', $n );     // MySQL versioned comment opener.
		$n = preg_replace( '~/\*.*?\*/~s', ' ', $n );  // Complete comments.
		$n = str_replace( '*/', ' ', (string) $n );      // Leftover closers.
		return (string) $n;
	}

	private function param_allowed( $rule_id, $param ) {
		$path = $this->path();
		foreach ( (array) $this->cfg( 'param_allowlist', array() ) as $row ) {
			if ( ! is_array( $row ) || count( $row ) < 3 ) {
				continue;
			}
			list( $p, $name, $rule ) = $row;
			if ( '*' !== $p && $p !== $path && ! ( '*' === substr( $p, -1 ) && 0 === strpos( $path, rtrim( $p, '*' ) ) ) ) {
				continue;
			}
			if ( '*' !== $name && $name !== $param ) {
				continue;
			}
			if ( '*' !== $rule && $rule !== $rule_id ) {
				continue;
			}
			return true;
		}
		return false;
	}

	/* ================================================================= helpers */

	public function path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$path = parse_url( $uri, PHP_URL_PATH );
		return is_string( $path ) && '' !== $path ? $path : '/';
	}

	public function has_auth_cookie() {
		foreach ( $_COOKIE as $k => $v ) {
			if ( 0 === strpos( (string) $k, 'wordpress_logged_in_' ) ) {
				return true;
			}
		}
		return false;
	}

	public function is_login_page( $path ) {
		return (bool) preg_match( '~/(?:wp-login|xmlrpc)\.php$~i', $path );
	}

	public function is_login_attempt( $path ) {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET';
		if ( preg_match( '~/xmlrpc\.php$~i', $path ) ) {
			return true;
		}
		if ( 'POST' === $method && preg_match( '~/wp-login\.php$~i', $path ) ) {
			$action = isset( $_GET['action'] ) ? (string) $_GET['action'] : 'login';
			return in_array( $action, array( 'login', '' ), true ) || ! empty( $_POST['pwd'] );
		}
		return false;
	}

	public function country() {
		if ( null !== $this->country ) {
			return $this->country;
		}
		$cc     = '';
		$remote = Bastion_IP::normalize( isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '' );
		if ( ! empty( $_SERVER['HTTP_CF_IPCOUNTRY'] ) && Bastion_IP::is_cloudflare( $remote ) ) {
			$cc = $_SERVER['HTTP_CF_IPCOUNTRY'];
		} elseif ( ! empty( $_SERVER['GEOIP_COUNTRY_CODE'] ) ) {
			$cc = $_SERVER['GEOIP_COUNTRY_CODE'];
		} elseif ( ! empty( $_SERVER['MM_COUNTRY_CODE'] ) ) {
			$cc = $_SERVER['MM_COUNTRY_CODE'];
		}
		$cc            = strtoupper( substr( preg_replace( '/[^A-Za-z0-9]/', '', (string) $cc ), 0, 2 ) );
		$this->country = $cc;
		return $cc;
	}

	public function count_attack( $weight ) {
		$threshold = (int) $this->cfg( 'auto_block_threshold', 0 );
		if ( $threshold <= 0 || 'learning' === $this->cfg( 'mode', 'block' ) ) {
			return;
		}
		$n = $this->storage->hit( 'atk:' . $this->ip, 600, $weight );
		if ( $n >= $threshold && $n - $weight < $threshold ) {
			$secs = max( 60, (int) $this->cfg( 'auto_block_seconds', 3600 ) );
			$this->storage->add_block( $this->ip, $secs, 'Repeated attacks (' . $n . ' malicious requests in 10 min)', 'all' );
			$this->log( 'auto_block', 'IP blocked automatically after repeated attacks', array( 'until' => time() + $secs ) );
		}
	}

	public function log( $type, $message, array $ctx = array() ) {
		$entry = array(
			't'      => time(),
			'id'     => $this->request_id,
			'ip'     => $this->ip,
			'type'   => $type,
			'msg'    => substr( (string) $message, 0, 300 ),
			'method' => isset( $_SERVER['REQUEST_METHOD'] ) ? substr( (string) $_SERVER['REQUEST_METHOD'], 0, 10 ) : '',
			'uri'    => isset( $_SERVER['REQUEST_URI'] ) ? substr( (string) $_SERVER['REQUEST_URI'], 0, 500 ) : '',
			'ua'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( (string) $_SERVER['HTTP_USER_AGENT'], 0, 300 ) : '',
			'cc'     => $this->country(),
		);
		foreach ( array( 'rule', 'cat', 'param', 'match' ) as $k ) {
			if ( isset( $ctx[ $k ] ) ) {
				$entry[ $k ] = substr( (string) $ctx[ $k ], 0, 300 );
			}
		}
		$this->storage->log( $entry );
	}

	/** Learning mode: automatic rules only log what they would have blocked. */
	public function learning() {
		return 'learning' === $this->cfg( 'mode', 'block' );
	}

	/**
	 * In learning mode, log "would block" (once per 5 minutes per IP and rule when throttled)
	 * and return true so the caller lets the request through. Manual blocks, country blocks
	 * and login lockouts are deliberate and always apply; they don't call this.
	 */
	public function only_learning( $type, $message, array $ctx = array() ) {
		if ( ! $this->learning() ) {
			return false;
		}
		if ( empty( $ctx['throttle_log'] ) || 1 === $this->storage->hit( 'lt:learn-' . $type . ':' . $this->ip, 300 ) ) {
			$ctx['cat'] = isset( $ctx['cat'] ) ? $ctx['cat'] : $type;
			$this->log( 'learning', 'Would block: ' . $message, $ctx );
		}
		return true;
	}

	/** Block the request and stop. */
	public function deny( $type, $message, array $ctx = array() ) {
		$log = true;
		if ( ! empty( $ctx['throttle_log'] ) ) {
			// Repeat hits from an already-blocked IP: log at most once per 5 minutes.
			$log = 1 === $this->storage->hit( 'lt:' . $type . ':' . $this->ip, 300 );
		}
		if ( $log ) {
			$this->log( $type, $message, $ctx );
		}
		$status = isset( $ctx['status'] ) ? (int) $ctx['status'] : 403;
		$this->respond( $status, $type );
	}

	private function respond( $status, $type ) {
		while ( ob_get_level() > 0 ) {
			@ob_end_clean();
		}
		$title = 429 === $status ? 'Too many requests' : 'Access denied';
		$text  = 'lockout' === $type
			? 'Too many failed login attempts from your network. Please try again later.'
			: ( 429 === $status ? 'You are sending requests too quickly. Please wait a few minutes and try again.' : 'Your request was blocked by this site\'s security firewall.' );
		$json  = ( isset( $_SERVER['HTTP_ACCEPT'] ) && false !== stripos( $_SERVER['HTTP_ACCEPT'], 'application/json' ) )
			|| false !== strpos( $this->path(), '/wp-json/' );

		if ( ! headers_sent() ) {
			http_response_code( $status );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			header( 'X-Robots-Tag: noindex, nofollow' );
			header( 'X-Content-Type-Options: nosniff' );
			if ( 429 === $status ) {
				header( 'Retry-After: 300' );
			}
			header( 'Content-Type: ' . ( $json ? 'application/json' : 'text/html' ) . '; charset=UTF-8' );
		}

		if ( $json ) {
			echo json_encode(
				array(
					'code'    => 'bastion_blocked',
					'message' => $text,
					'data'    => array( 'status' => $status, 'reference' => $this->request_id ),
				)
			);
			exit;
		}

		$ip = htmlspecialchars( $this->ip, ENT_QUOTES, 'UTF-8' );
		echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>' . $title . '</title>'
			. '<style>body{margin:0;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center}'
			. 'main{background:#fff;max-width:480px;margin:16px;padding:32px;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.08)}h1{font-size:22px;margin:0 0 8px}p{margin:0 0 16px;color:#50575e}'
			. 'dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:13px;color:#646970;margin:0}dd{margin:0;font-family:ui-monospace,Menlo,monospace}</style></head>'
			. '<body><main><h1>' . $title . '</h1><p>' . $text . '</p><p>If you believe this is a mistake, contact the site owner and quote the reference below.</p>'
			. '<dl><dt>Reference</dt><dd>' . $this->request_id . '</dd><dt>Your IP</dt><dd>' . $ip . '</dd><dt>Time</dt><dd>' . gmdate( 'Y-m-d H:i:s' ) . ' UTC</dd></dl></main></body></html>';
		exit;
	}
}
