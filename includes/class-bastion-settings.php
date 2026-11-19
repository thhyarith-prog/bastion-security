<?php
/**
 * Settings: schema-driven so every field is validated the same way and the admin
 * forms are generated from one definition.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Settings {

	const OPTION = 'bastion_settings';

	/** @var array|null */
	private static $cache;

	/**
	 * Field schema. type: bool | int | select | list | text | email | roles | checks.
	 */
	public static function schema() {
		// Labels are only translated once WordPress is ready to load translations (init);
		// before that only types and defaults are needed.
		$t = did_action( 'init' ) ? '__' : array( __CLASS__, 'untranslated' );
		$minute = $t( 'minutes', 'bastion-security' );
		return array(
			// ------------------------------------------------------------ Firewall
			'waf_enabled'          => array( 'section' => 'firewall', 'type' => 'bool', 'default' => true, 'label' => $t( 'Enable firewall', 'bastion-security' ) ),
			'waf_mode'             => array(
				'section' => 'firewall', 'type' => 'select', 'default' => 'block',
				'label'   => $t( 'Firewall mode', 'bastion-security' ),
				'options' => array( 'block' => $t( 'Protect (block attacks)', 'bastion-security' ), 'learning' => $t( 'Learning (log only, never block)', 'bastion-security' ) ),
				'desc'    => $t( 'Administrators are never inspected, so learning mode is only needed if a plugin of yours legitimately sends unusual data.', 'bastion-security' ),
			),
			'waf_block_bad_ua'     => array( 'section' => 'firewall', 'type' => 'bool', 'default' => true, 'label' => $t( 'Block vulnerability scanners and attack tools', 'bastion-security' ) ),
			'waf_block_probes'     => array( 'section' => 'firewall', 'type' => 'bool', 'default' => true, 'label' => $t( 'Block probes for secrets, backups and web shells', 'bastion-security' ), 'desc' => $t( '.env, .git, wp-config backups, SQL dumps, debug.log, phpinfo, known shell names…', 'bastion-security' ) ),
			'waf_block_php_uploads' => array( 'section' => 'firewall', 'type' => 'bool', 'default' => true, 'label' => $t( 'Block executable file uploads', 'bastion-security' ), 'desc' => $t( 'Stops .php uploads and images with hidden PHP code from non-administrators.', 'bastion-security' ) ),
			'auto_block_threshold' => array( 'section' => 'firewall', 'type' => 'int', 'default' => 5, 'min' => 0, 'max' => 1000, 'label' => $t( 'Auto-block attackers after', 'bastion-security' ), 'suffix' => $t( 'malicious requests in 10 minutes (0 = off)', 'bastion-security' ) ),
			'auto_block_minutes'   => array( 'section' => 'firewall', 'type' => 'int', 'default' => 60, 'min' => 1, 'max' => 43200, 'label' => $t( 'Auto-block duration', 'bastion-security' ), 'suffix' => $minute ),
			'rate_limit_rpm'       => array( 'section' => 'firewall', 'type' => 'int', 'default' => 600, 'min' => 0, 'max' => 100000, 'label' => $t( 'Rate limit', 'bastion-security' ), 'suffix' => $t( 'PHP requests per minute per IP (0 = off)', 'bastion-security' ) ),
			'rate_limit_minutes'   => array( 'section' => 'firewall', 'type' => 'int', 'default' => 10, 'min' => 1, 'max' => 1440, 'label' => $t( 'Rate limit block duration', 'bastion-security' ), 'suffix' => $minute ),
			'rate_404_per_min'     => array( 'section' => 'firewall', 'type' => 'int', 'default' => 40, 'min' => 0, 'max' => 10000, 'label' => $t( '404 limit', 'bastion-security' ), 'suffix' => $t( 'not-found pages per minute per IP (0 = off)', 'bastion-security' ) ),
			'ip_mode'              => array(
				'section' => 'firewall', 'type' => 'select', 'default' => 'auto',
				'label'   => $t( 'How to get visitor IPs', 'bastion-security' ),
				'options' => array(
					'auto'            => $t( 'Automatic (REMOTE_ADDR, Cloudflare when verified)', 'bastion-security' ),
					'remote_addr'     => $t( 'REMOTE_ADDR only (no proxy)', 'bastion-security' ),
					'cloudflare'      => $t( 'Cloudflare (CF-Connecting-IP)', 'bastion-security' ),
					'x_forwarded_for' => $t( 'X-Forwarded-For (from trusted proxies)', 'bastion-security' ),
					'x_real_ip'       => $t( 'X-Real-IP (from trusted proxies)', 'bastion-security' ),
				),
				'desc'    => $t( 'Proxy headers are only trusted when the request really comes from that proxy, so attackers cannot fake their IP.', 'bastion-security' ),
			),
			'trusted_proxies'      => array( 'section' => 'firewall', 'type' => 'list', 'default' => array(), 'label' => $t( 'Trusted proxies', 'bastion-security' ), 'desc' => $t( 'One IP or CIDR per line. Private networks are always trusted.', 'bastion-security' ), 'validate' => 'ip' ),
			'ip_allowlist'         => array( 'section' => 'firewall', 'type' => 'list', 'default' => array(), 'label' => $t( 'Allowlisted IPs', 'bastion-security' ), 'desc' => $t( 'Never blocked or rate limited. One IP or CIDR per line.', 'bastion-security' ), 'validate' => 'ip' ),
			'ip_blocklist'         => array( 'section' => 'firewall', 'type' => 'list', 'default' => array(), 'label' => $t( 'Permanently blocked IPs', 'bastion-security' ), 'desc' => $t( 'One IP or CIDR per line.', 'bastion-security' ), 'validate' => 'ip' ),
			'country_block'        => array( 'section' => 'firewall', 'type' => 'list', 'default' => array(), 'label' => $t( 'Blocked countries', 'bastion-security' ), 'desc' => $t( 'Two-letter codes (e.g. RU, CN; T1 = Tor). Needs Cloudflare or a GeoIP server module.', 'bastion-security' ), 'validate' => 'country' ),
			'country_scope'        => array( 'section' => 'firewall', 'type' => 'select', 'default' => 'login', 'label' => $t( 'Country block applies to', 'bastion-security' ), 'options' => array( 'login' => $t( 'Login and XML-RPC only', 'bastion-security' ), 'all' => $t( 'The whole site', 'bastion-security' ) ) ),
			'disabled_rules'       => array( 'section' => 'hidden', 'type' => 'list', 'default' => array() ),
			'param_allowlist'      => array( 'section' => 'hidden', 'type' => 'raw', 'default' => array(
				array( '/wp-comments-post.php', 'post:comment', 'rce-phptag' ),
				array( '/wp-comments-post.php', 'post:comment', 'rce-phpfunc' ),
				array( '/wp-comments-post.php', 'post:comment', 'lfi-wpconfig' ),
				array( '/wp-comments-post.php', 'post:comment', 'sqli-schema' ),
				array( '/wp-comments-post.php', 'post:comment', 'sqli-union' ),
			) ),

			// --------------------------------------------------------------- Login
			'login_max_attempts'   => array( 'section' => 'login', 'type' => 'int', 'default' => 5, 'min' => 1, 'max' => 100, 'label' => $t( 'Lock out after', 'bastion-security' ), 'suffix' => $t( 'failed logins', 'bastion-security' ) ),
			'login_window_minutes' => array( 'section' => 'login', 'type' => 'int', 'default' => 15, 'min' => 1, 'max' => 1440, 'label' => $t( '…within', 'bastion-security' ), 'suffix' => $minute ),
			'login_lockout_minutes' => array( 'section' => 'login', 'type' => 'int', 'default' => 30, 'min' => 1, 'max' => 43200, 'label' => $t( 'Lockout duration', 'bastion-security' ), 'suffix' => $minute ),
			'login_progressive'    => array( 'section' => 'login', 'type' => 'bool', 'default' => true, 'label' => $t( 'Double the lockout for repeat offenders (up to 24 hours)', 'bastion-security' ) ),
			'login_block_usernames' => array( 'section' => 'login', 'type' => 'list', 'default' => array( 'admin', 'administrator', 'root', 'test', 'user', 'wpadmin', 'demo' ), 'label' => $t( 'Instantly lock out logins as', 'bastion-security' ), 'desc' => $t( 'Only applies when no account with that name exists.', 'bastion-security' ) ),
			'login_generic_errors' => array( 'section' => 'login', 'type' => 'bool', 'default' => true, 'label' => $t( 'Hide whether the username or the password was wrong', 'bastion-security' ) ),
			'block_user_enum'      => array( 'section' => 'login', 'type' => 'bool', 'default' => true, 'label' => $t( 'Block username discovery', 'bastion-security' ), 'desc' => $t( '?author=N scans, the public REST users list, user sitemaps and oEmbed author names.', 'bastion-security' ) ),
			'xmlrpc_mode'          => array(
				'section' => 'login', 'type' => 'select', 'default' => 'restrict',
				'label'   => $t( 'XML-RPC', 'bastion-security' ),
				'options' => array(
					'restrict' => $t( 'Restricted: no multicall, no pingbacks (recommended)', 'bastion-security' ),
					'disable'  => $t( 'Disabled completely', 'bastion-security' ),
					'allow'    => $t( 'Allowed (WordPress default)', 'bastion-security' ),
				),
			),
			'disable_app_passwords' => array( 'section' => 'login', 'type' => 'bool', 'default' => false, 'label' => $t( 'Disable application passwords', 'bastion-security' ) ),
			'lostpassword_limit'   => array( 'section' => 'login', 'type' => 'int', 'default' => 5, 'min' => 0, 'max' => 100, 'label' => $t( 'Password reset requests', 'bastion-security' ), 'suffix' => $t( 'per IP per 15 minutes (0 = unlimited)', 'bastion-security' ) ),
			'tfa_required_roles'   => array( 'section' => 'login', 'type' => 'roles', 'default' => array( 'administrator' ), 'label' => $t( 'Require two-factor for', 'bastion-security' ) ),
			'tfa_grace_days'       => array( 'section' => 'login', 'type' => 'int', 'default' => 7, 'min' => 0, 'max' => 90, 'label' => $t( 'Two-factor grace period', 'bastion-security' ), 'suffix' => $t( 'days before setup is forced', 'bastion-security' ) ),
			'tfa_remember_days'    => array( 'section' => 'login', 'type' => 'int', 'default' => 30, 'min' => 0, 'max' => 365, 'label' => $t( '"Remember this device" for', 'bastion-security' ), 'suffix' => $t( 'days (0 = always ask)', 'bastion-security' ) ),
			'password_roles'       => array( 'section' => 'login', 'type' => 'roles', 'default' => array( 'administrator', 'editor', 'shop_manager' ), 'label' => $t( 'Enforce strong passwords for', 'bastion-security' ) ),
			'password_min_length'  => array( 'section' => 'login', 'type' => 'int', 'default' => 12, 'min' => 8, 'max' => 64, 'label' => $t( 'Minimum password length', 'bastion-security' ), 'suffix' => $t( 'characters', 'bastion-security' ) ),
			'password_breach_check' => array( 'section' => 'login', 'type' => 'bool', 'default' => true, 'label' => $t( 'Reject passwords found in data breaches', 'bastion-security' ), 'desc' => $t( 'Uses the Have I Been Pwned k-anonymity API: only the first 5 characters of a SHA-1 hash leave your server.', 'bastion-security' ) ),

			// ----------------------------------------------------------- Hardening
			'disable_file_editor'  => array( 'section' => 'hardening', 'type' => 'bool', 'default' => true, 'label' => $t( 'Disable the theme and plugin file editor', 'bastion-security' ) ),
			'hide_wp_version'      => array( 'section' => 'hardening', 'type' => 'bool', 'default' => true, 'label' => $t( 'Hide the WordPress version', 'bastion-security' ) ),
			'security_headers'     => array( 'section' => 'hardening', 'type' => 'bool', 'default' => true, 'label' => $t( 'Send security headers', 'bastion-security' ), 'desc' => $t( 'X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.', 'bastion-security' ) ),
			'hsts'                 => array( 'section' => 'hardening', 'type' => 'bool', 'default' => false, 'label' => $t( 'Send HSTS (force HTTPS for 1 year)', 'bastion-security' ), 'desc' => $t( 'Only enable when the whole site, including subdomains you use, works on HTTPS.', 'bastion-security' ) ),
			'uploads_php_block'    => array( 'section' => 'hardening', 'type' => 'bool', 'default' => true, 'label' => $t( 'Block PHP execution in the uploads folder', 'bastion-security' ), 'desc' => $t( 'Writes an .htaccess rule (Apache/LiteSpeed). On Nginx add the rule shown on the dashboard.', 'bastion-security' ) ),

			// ------------------------------------------------------------- Scanner
			'scan_schedule'        => array( 'section' => 'scanner', 'type' => 'select', 'default' => 'daily', 'label' => $t( 'Automatic scans', 'bastion-security' ), 'options' => array( 'daily' => $t( 'Daily', 'bastion-security' ), 'weekly' => $t( 'Weekly', 'bastion-security' ), 'off' => $t( 'Off', 'bastion-security' ) ) ),
			'scan_signatures'      => array( 'section' => 'scanner', 'type' => 'bool', 'default' => true, 'label' => $t( 'Scan files for malware signatures', 'bastion-security' ) ),
			'scan_plugin_integrity' => array( 'section' => 'scanner', 'type' => 'bool', 'default' => true, 'label' => $t( 'Compare plugin files with WordPress.org originals', 'bastion-security' ) ),
			'scan_vulnerabilities' => array( 'section' => 'scanner', 'type' => 'bool', 'default' => true, 'label' => $t( 'Check for known vulnerabilities', 'bastion-security' ), 'desc' => $t( 'Looks up core, plugin and theme versions in the free WPVulnerability.net database (only slugs and versions are sent).', 'bastion-security' ) ),
			'scan_abandoned'       => array( 'section' => 'scanner', 'type' => 'bool', 'default' => true, 'label' => $t( 'Flag plugins closed or abandoned on WordPress.org', 'bastion-security' ) ),
			'scan_database'        => array( 'section' => 'scanner', 'type' => 'bool', 'default' => true, 'label' => $t( 'Scan posts and options for injected scripts', 'bastion-security' ) ),
			'scan_max_file_mb'     => array( 'section' => 'scanner', 'type' => 'int', 'default' => 4, 'min' => 1, 'max' => 64, 'label' => $t( 'Skip signature checks on files larger than', 'bastion-security' ), 'suffix' => 'MB' ),
			'scan_exclude'         => array( 'section' => 'scanner', 'type' => 'list', 'default' => array( 'wp-content/cache/', 'wp-content/updraft/', 'wp-content/ai1wm-backups/', 'node_modules/', '.git/' ), 'label' => $t( 'Exclude paths containing', 'bastion-security' ) ),

			// ------------------------------------------------------------ Comments
			'comment_shield'       => array(
				'section' => 'comments', 'type' => 'select', 'default' => 'on',
				'label'   => $t( 'Comment spam shield', 'bastion-security' ),
				'options' => array( 'on' => $t( 'On: block spam bots', 'bastion-security' ), 'log' => $t( 'Watch only: log what would be blocked', 'bastion-security' ), 'off' => $t( 'Off', 'bastion-security' ) ),
			),
			'comment_honeypot'     => array( 'section' => 'comments', 'type' => 'bool', 'default' => true, 'label' => $t( 'Hidden trap field (honeypot)', 'bastion-security' ), 'desc' => $t( 'An invisible field that people never see but bots fill in.', 'bastion-security' ) ),
			'comment_js_token'     => array( 'section' => 'comments', 'type' => 'bool', 'default' => true, 'label' => $t( 'Browser check', 'bastion-security' ), 'desc' => $t( 'The comment form gets a one-time token from your site when someone starts typing. Most spam bots post directly and never have one. Works with page caching.', 'bastion-security' ) ),
			'comment_no_js_action' => array( 'section' => 'comments', 'type' => 'select', 'default' => 'reject', 'label' => $t( 'Comments without the browser check', 'bastion-security' ), 'options' => array( 'reject' => $t( 'Reject (recommended)', 'bastion-security' ), 'hold' => $t( 'Hold for moderation', 'bastion-security' ) ), 'desc' => $t( 'People with JavaScript turned off are told to turn it on.', 'bastion-security' ) ),
			'comment_min_seconds'  => array( 'section' => 'comments', 'type' => 'int', 'default' => 3, 'min' => 0, 'max' => 120, 'label' => $t( 'Reject comments written faster than', 'bastion-security' ), 'suffix' => $t( 'seconds (0 = off)', 'bastion-security' ) ),
			'comment_max_links'    => array( 'section' => 'comments', 'type' => 'int', 'default' => 2, 'min' => 0, 'max' => 50, 'label' => $t( 'Send to spam when a comment has more than', 'bastion-security' ), 'suffix' => $t( 'links (0 = off)', 'bastion-security' ) ),
			'comment_blocklist'    => array( 'section' => 'comments', 'type' => 'list', 'default' => array( 'casino', 'viagra', 'cialis', 'porn', 'xxx', 'escort', 'payday loan', '1xbet', 'betting', 'backlinks', 'seo service', 'crypto signal', 'forex signal' ), 'label' => $t( 'Spam words', 'bastion-security' ), 'desc' => $t( 'One word or phrase per line. A comment containing one goes to spam (whole words only).', 'bastion-security' ) ),
			'comment_block_scripts' => array(
				'section' => 'comments', 'type' => 'checks', 'default' => array(),
				'label'   => $t( 'Send to spam when a comment is mostly written in', 'bastion-security' ),
				'options' => array( 'cyrillic' => $t( 'Cyrillic (Russian…)', 'bastion-security' ), 'han' => $t( 'Chinese', 'bastion-security' ), 'hangul' => $t( 'Korean', 'bastion-security' ), 'arabic' => $t( 'Arabic', 'bastion-security' ), 'hebrew' => $t( 'Hebrew', 'bastion-security' ), 'devanagari' => $t( 'Hindi (Devanagari)', 'bastion-security' ), 'greek' => $t( 'Greek', 'bastion-security' ) ),
				'desc'    => $t( 'Tick only alphabets your real visitors never use.', 'bastion-security' ),
			),
			'comment_remove_url'   => array( 'section' => 'comments', 'type' => 'bool', 'default' => false, 'label' => $t( 'Remove the "Website" field from the comment form', 'bastion-security' ), 'desc' => $t( 'Most comment spam exists only to get a link. Without the field there is nothing to gain.', 'bastion-security' ) ),
			'comment_block_pings'  => array( 'section' => 'comments', 'type' => 'bool', 'default' => true, 'label' => $t( 'Block pingbacks and trackbacks', 'bastion-security' ), 'desc' => $t( 'Old link notifications between blogs, today used almost only by spammers.', 'bastion-security' ) ),
			'comment_rate_per_hour' => array( 'section' => 'comments', 'type' => 'int', 'default' => 6, 'min' => 0, 'max' => 1000, 'label' => $t( 'Limit comments to', 'bastion-security' ), 'suffix' => $t( 'per IP per hour (0 = no limit)', 'bastion-security' ) ),
			'comment_autoblock'    => array( 'section' => 'comments', 'type' => 'bool', 'default' => true, 'label' => $t( 'Count blocked spam bots as attacks', 'bastion-security' ), 'desc' => $t( 'A bot that keeps trying is blocked from the whole site by the firewall\'s auto-block.', 'bastion-security' ) ),

			// ------------------------------------------------------------ Visitors
			'visitors_enabled'     => array( 'section' => 'visitors', 'type' => 'bool', 'default' => false, 'label' => $t( 'Count visitors', 'bastion-security' ) ),
			'visitors_exclude'     => array( 'section' => 'visitors', 'type' => 'select', 'default' => 'editors', 'label' => $t( 'Don\'t count', 'bastion-security' ), 'options' => array( 'editors' => $t( 'People who can edit the site', 'bastion-security' ), 'logged_in' => $t( 'Everyone who is logged in', 'bastion-security' ), 'none' => $t( 'Nobody (count everyone)', 'bastion-security' ) ) ),
			'visitors_respect_dnt' => array( 'section' => 'visitors', 'type' => 'bool', 'default' => true, 'label' => $t( 'Respect "Do Not Track" and Global Privacy Control', 'bastion-security' ), 'desc' => $t( 'Browsers that ask not to be tracked are not counted.', 'bastion-security' ) ),

			// ------------------------------------------------------------- General
			'alert_email'         => array( 'section' => 'general', 'type' => 'email', 'default' => '', 'label' => $t( 'Alert email', 'bastion-security' ), 'desc' => $t( 'Leave empty to use the site admin email.', 'bastion-security' ) ),
			'alert_new_admin'      => array( 'section' => 'general', 'type' => 'bool', 'default' => true, 'label' => $t( 'Alert when an administrator account is created or granted', 'bastion-security' ) ),
			'alert_admin_new_ip'   => array( 'section' => 'general', 'type' => 'bool', 'default' => true, 'label' => $t( 'Alert when an administrator signs in from a new IP', 'bastion-security' ) ),
			'alert_scan'           => array( 'section' => 'general', 'type' => 'bool', 'default' => true, 'label' => $t( 'Alert when a scan finds new high or critical issues', 'bastion-security' ) ),
			'alert_plugins'        => array( 'section' => 'general', 'type' => 'bool', 'default' => false, 'label' => $t( 'Alert when plugins or themes are installed, activated or removed', 'bastion-security' ) ),
			'alert_lockouts'       => array( 'section' => 'general', 'type' => 'bool', 'default' => false, 'label' => $t( 'Alert on login lockouts (max one email per hour)', 'bastion-security' ) ),
			'log_retention_days'   => array( 'section' => 'general', 'type' => 'int', 'default' => 60, 'min' => 1, 'max' => 3650, 'label' => $t( 'Keep activity log for', 'bastion-security' ), 'suffix' => $t( 'days', 'bastion-security' ) ),
			'delete_on_uninstall'  => array( 'section' => 'general', 'type' => 'bool', 'default' => false, 'label' => $t( 'Delete all Bastion data when the plugin is uninstalled', 'bastion-security' ) ),
		);
	}

	public static function untranslated( $text ) {
		return $text;
	}

	public static function defaults() {
		$out = array();
		foreach ( self::schema() as $key => $field ) {
			$out[ $key ] = $field['default'];
		}
		return $out;
	}

	public static function all() {
		if ( null === self::$cache ) {
			$saved       = get_option( self::OPTION, array() );
			self::$cache = array_merge( self::defaults(), is_array( $saved ) ? $saved : array() );
		}
		return self::$cache;
	}

	public static function get( $key ) {
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	/**
	 * Merge new values into the stored settings (validated against the schema).
	 */
	public static function update( array $values ) {
		$schema = self::schema();
		$all    = self::all();
		foreach ( $values as $key => $value ) {
			if ( isset( $schema[ $key ] ) ) {
				$all[ $key ] = self::sanitize( $schema[ $key ], $value );
			}
		}
		update_option( self::OPTION, $all, true );
		self::$cache = $all;
		do_action( 'bastion_settings_updated', $all );
		return $all;
	}

	/**
	 * Read a submitted form section; unchecked checkboxes are absent from $_POST, so every
	 * field of the section is resolved explicitly.
	 */
	public static function from_request( $section, array $input ) {
		$values = array();
		foreach ( self::schema() as $key => $field ) {
			if ( $field['section'] !== $section ) {
				continue;
			}
			if ( 'bool' === $field['type'] ) {
				$values[ $key ] = ! empty( $input[ $key ] );
			} elseif ( 'roles' === $field['type'] || 'checks' === $field['type'] ) {
				$values[ $key ] = isset( $input[ $key ] ) ? (array) $input[ $key ] : array();
			} elseif ( array_key_exists( $key, $input ) ) {
				$values[ $key ] = wp_unslash( $input[ $key ] );
			}
		}
		return $values;
	}

	public static function sanitize( array $field, $value ) {
		switch ( $field['type'] ) {
			case 'bool':
				return (bool) $value;
			case 'int':
				$v = (int) $value;
				if ( isset( $field['min'] ) ) {
					$v = max( $field['min'], $v );
				}
				if ( isset( $field['max'] ) ) {
					$v = min( $field['max'], $v );
				}
				return $v;
			case 'select':
				return isset( $field['options'][ $value ] ) ? $value : $field['default'];
			case 'email':
				return sanitize_email( (string) $value );
			case 'text':
				return sanitize_text_field( (string) $value );
			case 'roles':
				$roles = array_keys( wp_roles()->roles );
				return array_values( array_intersect( array_map( 'sanitize_key', (array) $value ), $roles ) );
			case 'checks':
				return array_values( array_intersect( array_map( 'sanitize_key', (array) $value ), array_keys( $field['options'] ) ) );
			case 'list':
				$lines = is_array( $value ) ? $value : preg_split( '/[\r\n,]+/', (string) $value );
				$out   = array();
				foreach ( $lines as $line ) {
					$line = trim( sanitize_text_field( (string) $line ) );
					if ( '' === $line ) {
						continue;
					}
					if ( isset( $field['validate'] ) && 'ip' === $field['validate'] ) {
						$ip = strpos( $line, '/' ) !== false ? explode( '/', $line, 2 ) : array( $line );
						if ( false === filter_var( $ip[0], FILTER_VALIDATE_IP ) || ( isset( $ip[1] ) && ! ctype_digit( $ip[1] ) ) ) {
							continue;
						}
					}
					if ( isset( $field['validate'] ) && 'country' === $field['validate'] ) {
						$line = strtoupper( $line );
						if ( ! preg_match( '/^[A-Z][A-Z0-9]$/', $line ) ) {
							continue;
						}
					}
					$out[] = $line;
				}
				return array_values( array_unique( $out ) );
			case 'raw':
				return is_array( $value ) ? $value : $field['default'];
		}
		return $value;
	}

	public static function alert_email() {
		$email = self::get( 'alert_email' );
		return $email ? $email : get_option( 'admin_email' );
	}
}
