<?php
/**
 * Hardening toggles and the security checklist that feeds the dashboard score.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Hardening {

	const UPLOADS_MARKER = 'Bastion Security';

	public static function init() {
		if ( Bastion_Settings::get( 'disable_file_editor' ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
		if ( Bastion_Settings::get( 'hide_wp_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}
		if ( Bastion_Settings::get( 'security_headers' ) || Bastion_Settings::get( 'hsts' ) ) {
			add_action( 'send_headers', array( __CLASS__, 'headers' ) );
			add_action( 'login_init', array( __CLASS__, 'headers' ) );
			add_action( 'admin_init', array( __CLASS__, 'headers' ) );
		}
		add_action( 'bastion_settings_updated', array( __CLASS__, 'sync_uploads_rule' ) );
	}

	public static function headers() {
		if ( headers_sent() ) {
			return;
		}
		if ( Bastion_Settings::get( 'security_headers' ) ) {
			header( 'X-Content-Type-Options: nosniff' );
			header( 'X-Frame-Options: SAMEORIGIN' );
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );
			header( 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()' );
			header( 'Cross-Origin-Opener-Policy: same-origin-allow-popups' );
		}
		if ( Bastion_Settings::get( 'hsts' ) && is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
		}
	}

	/** Write or remove the "no PHP in uploads" rule. */
	public static function sync_uploads_rule() {
		$uploads = wp_upload_dir( null, false );
		if ( empty( $uploads['basedir'] ) || ! is_dir( $uploads['basedir'] ) ) {
			return false;
		}
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		$file  = trailingslashit( $uploads['basedir'] ) . '.htaccess';
		$lines = array();
		if ( Bastion_Settings::get( 'uploads_php_block' ) ) {
			$lines = array(
				'<FilesMatch "\.(?i:php[0-9]?|phtml|phar|pht|phps|pl|py|cgi|shtml)$">',
				'  <IfModule mod_authz_core.c>',
				'    Require all denied',
				'  </IfModule>',
				'  <IfModule !mod_authz_core.c>',
				'    Order allow,deny',
				'    Deny from all',
				'  </IfModule>',
				'</FilesMatch>',
			);
		}
		if ( ! $lines && ! is_file( $file ) ) {
			return true;
		}
		return insert_with_markers( $file, self::UPLOADS_MARKER, $lines );
	}

	public static function nginx_snippet() {
		$uploads = wp_upload_dir( null, false );
		$path    = wp_parse_url( $uploads['baseurl'], PHP_URL_PATH );
		return "location ~* ^" . $path . "/.*\\.(php[0-9]?|phtml|phar|pht|phps)$ {\n    deny all;\n}\nlocation ~* /wp-content/bastion-waf/ {\n    deny all;\n}";
	}

	/**
	 * Security checklist.
	 *
	 * @return array[] id, status (pass|warn|fail), weight, title, detail, fix (URL or text).
	 */
	public static function checks() {
		global $wpdb;
		$checks = array();
		$add    = function ( $id, $ok, $weight, $title, $detail, $fix = '', $warn_only = false ) use ( &$checks ) {
			$checks[] = array(
				'id'     => $id,
				'status' => $ok ? 'pass' : ( $warn_only ? 'warn' : 'fail' ),
				'weight' => $weight,
				'title'  => $title,
				'detail' => $detail,
				'fix'    => $fix,
			);
		};

		$settings_url = admin_url( 'admin.php?page=bastion-settings' );
		$fw_url       = admin_url( 'admin.php?page=bastion-firewall' );

		// Firewall.
		$status = Bastion_Firewall::status();
		$add( 'waf', 'disabled' !== $status, 15, __( 'Firewall enabled', 'bastion-security' ), __( 'The firewall blocks injection attacks, scanners and brute force before they reach WordPress.', 'bastion-security' ), $fw_url );
		$add( 'waf_extended', 'extended' === $status, 5, __( 'Firewall runs before WordPress', 'bastion-security' ), __( 'Extended protection also covers PHP files that attackers call directly, and is faster.', 'bastion-security' ), $fw_url, true );

		// Core / updates.
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$core = get_core_updates();
		$core_ok = ! ( is_array( $core ) && isset( $core[0]->response ) && 'upgrade' === $core[0]->response );
		$add( 'core_update', $core_ok, 10, __( 'WordPress is up to date', 'bastion-security' ), $core_ok ? __( 'You run the latest WordPress.', 'bastion-security' ) : sprintf( __( 'Version %s is available.', 'bastion-security' ), $core[0]->current ), admin_url( 'update-core.php' ) );

		$plugin_updates = get_site_transient( 'update_plugins' );
		$n_plugins      = isset( $plugin_updates->response ) ? count( (array) $plugin_updates->response ) : 0;
		$add( 'plugin_updates', 0 === $n_plugins, 10, __( 'Plugins are up to date', 'bastion-security' ), $n_plugins ? sprintf( _n( '%d plugin has an update. Outdated plugins are the #1 cause of hacked sites.', '%d plugins have updates. Outdated plugins are the #1 cause of hacked sites.', $n_plugins, 'bastion-security' ), $n_plugins ) : __( 'All plugins are current.', 'bastion-security' ), admin_url( 'update-core.php' ) );

		$theme_updates = get_site_transient( 'update_themes' );
		$n_themes      = isset( $theme_updates->response ) ? count( (array) $theme_updates->response ) : 0;
		$add( 'theme_updates', 0 === $n_themes, 4, __( 'Themes are up to date', 'bastion-security' ), $n_themes ? sprintf( _n( '%d theme has an update.', '%d themes have updates.', $n_themes, 'bastion-security' ), $n_themes ) : __( 'All themes are current.', 'bastion-security' ), admin_url( 'update-core.php' ) );

		// PHP.
		$php_ok = version_compare( PHP_VERSION, '8.2', '>=' );
		$add( 'php', $php_ok, 4, __( 'Supported PHP version', 'bastion-security' ), sprintf( __( 'PHP %s. Versions below 8.2 no longer receive security fixes.', 'bastion-security' ), PHP_VERSION ), __( 'Ask your host to upgrade PHP.', 'bastion-security' ), true );

		// HTTPS.
		$https = 0 === strpos( home_url(), 'https://' );
		$add( 'https', $https, 6, __( 'Site uses HTTPS', 'bastion-security' ), __( 'Without HTTPS, passwords and cookies travel in plain text.', 'bastion-security' ), admin_url( 'options-general.php' ) );

		// Login.
		$admins     = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login' ) ) );
		$no_2fa     = array();
		foreach ( $admins as $a ) {
			if ( ! Bastion_Two_Factor::is_enabled( $a->ID ) ) {
				$no_2fa[] = $a->user_login;
			}
		}
		$add( 'admin_2fa', ! $no_2fa, 12, __( 'All administrators use two-factor', 'bastion-security' ), $no_2fa ? sprintf( __( 'Without two-factor: %s', 'bastion-security' ), implode( ', ', array_slice( $no_2fa, 0, 6 ) ) ) : __( 'Every administrator has two-factor enabled.', 'bastion-security' ), admin_url( 'profile.php#bastion-2fa' ) );

		$admin_user = get_user_by( 'login', 'admin' );
		$add( 'admin_username', ! $admin_user, 4, __( 'No user called "admin"', 'bastion-security' ), __( '"admin" is the first username every bot tries.', 'bastion-security' ), admin_url( 'users.php' ) );

		$xml = Bastion_Settings::get( 'xmlrpc_mode' );
		$add( 'xmlrpc', 'allow' !== $xml, 4, __( 'XML-RPC restricted', 'bastion-security' ), __( 'Multicall lets bots try hundreds of passwords in one request.', 'bastion-security' ), admin_url( 'admin.php?page=bastion-login' ) );

		// Registration takeover.
		$role       = get_role( get_option( 'default_role' ) );
		$reg_danger = get_option( 'users_can_register' ) && $role && ( $role->has_cap( 'manage_options' ) || $role->has_cap( 'edit_users' ) || $role->has_cap( 'edit_others_posts' ) );
		$add( 'registration', ! $reg_danger, 15, __( 'Safe default role for new users', 'bastion-security' ), $reg_danger ? __( 'Anyone can register and receives a privileged role!', 'bastion-security' ) : __( 'New registrations get a low-privilege role.', 'bastion-security' ), admin_url( 'options-general.php' ) );

		// Config.
		$display = defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY );
		$add( 'debug_display', ! $display, 5, __( 'Errors are not shown to visitors', 'bastion-security' ), __( 'WP_DEBUG with display on leaks file paths and internals.', 'bastion-security' ), __( 'Set WP_DEBUG_DISPLAY to false in wp-config.php.', 'bastion-security' ) );

		$log = WP_CONTENT_DIR . '/debug.log';
		$add( 'debug_log', ! is_file( $log ) || Bastion_Settings::get( 'waf_block_probes' ), 4, __( 'debug.log is not public', 'bastion-security' ), __( 'wp-content/debug.log can contain secrets and is readable by anyone by default.', 'bastion-security' ), $fw_url );

		$editor = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		$add( 'file_editor', $editor, 4, __( 'File editor disabled', 'bastion-security' ), __( 'A stolen admin session could otherwise edit PHP code directly.', 'bastion-security' ), $settings_url );

		$config = is_file( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php';
		$perms  = is_file( $config ) ? fileperms( $config ) & 0777 : 0;
		$add( 'config_perms', ! $perms || ! ( $perms & 0002 ), 5, __( 'wp-config.php is not world-writable', 'bastion-security' ), sprintf( __( 'Current permissions: %o.', 'bastion-security' ), $perms ), __( 'Set permissions to 600 or 640.', 'bastion-security' ) );

		$add( 'db_prefix', 'wp_' !== $wpdb->prefix, 1, __( 'Custom database prefix', 'bastion-security' ), __( 'A non-default prefix makes automated SQL injection slightly harder.', 'bastion-security' ), '', true );

		$add( 'headers', (bool) Bastion_Settings::get( 'security_headers' ), 3, __( 'Security headers sent', 'bastion-security' ), __( 'Protects against clickjacking and MIME sniffing.', 'bastion-security' ), $settings_url );

		$add( 'uploads_php', (bool) Bastion_Settings::get( 'uploads_php_block' ), 4, __( 'PHP blocked in uploads', 'bastion-security' ), __( 'Stops uploaded backdoors from running.', 'bastion-security' ), $settings_url );

		$last = (int) get_option( 'bastion_last_scan_completed' );
		$add( 'scan_recent', $last > time() - 8 * DAY_IN_SECONDS, 6, __( 'Scanned in the last week', 'bastion-security' ), $last ? sprintf( __( 'Last scan: %s ago.', 'bastion-security' ), human_time_diff( $last ) ) : __( 'No scan has run yet.', 'bastion-security' ), admin_url( 'admin.php?page=bastion-scanner' ) );

		return $checks;
	}

	/**
	 * Score 0-100 from checks plus open scan issues.
	 */
	public static function score( array $checks, array $issue_counts ) {
		$total = 0;
		$got   = 0;
		foreach ( $checks as $c ) {
			$total += $c['weight'];
			if ( 'pass' === $c['status'] ) {
				$got += $c['weight'];
			} elseif ( 'warn' === $c['status'] ) {
				$got += $c['weight'] * 0.5;
			}
		}
		$score  = $total ? ( $got / $total ) * 100 : 100;
		$score -= 25 * (int) ( $issue_counts[4] ?? 0 ) + 10 * (int) ( $issue_counts[3] ?? 0 ) + 3 * (int) ( $issue_counts[2] ?? 0 );
		return (int) max( 0, min( 100, round( $score ) ) );
	}

	/**
	 * Findings for the Prasat Digital one-click site check (Prasat_Hub::run_check).
	 */
	public static function health() {
		$out = array();
		foreach ( self::checks() as $c ) {
			$w      = (int) $c['weight'];
			$is_url = is_string( $c['fix'] ) && 0 === strpos( $c['fix'], 'http' );
			$out[]  = array(
				'id'       => $c['id'],
				'status'   => $c['status'],
				'severity' => $w >= 15 ? 'critical' : ( $w >= 10 ? 'high' : ( $w >= 5 ? 'medium' : 'low' ) ),
				'title'    => $c['title'],
				'detail'   => $c['detail'] . ( ! $is_url && $c['fix'] && 'pass' !== $c['status'] ? ' ' . $c['fix'] : '' ),
				'fix_url'  => $is_url ? $c['fix'] : '',
			);
		}
		$counts  = Bastion_Scanner::issue_counts();
		$serious = (int) $counts[3] + (int) $counts[4];
		$scan    = admin_url( 'admin.php?page=bastion-scanner' );
		$out[]   = array( 'id' => 'scan_serious', 'status' => $serious ? 'fail' : 'pass', 'severity' => 'critical', 'title' => __( 'No serious problems found by the malware scan', 'bastion-security' ), 'detail' => $serious ? sprintf( _n( '%d serious issue (malware, a changed core file or a vulnerable plugin) needs a look.', '%d serious issues (malware, changed core files or vulnerable plugins) need a look.', $serious, 'bastion-security' ), $serious ) : __( 'The last scan found nothing serious.', 'bastion-security' ), 'fix_url' => $scan, 'fix_label' => __( 'Review', 'bastion-security' ) );
		if ( (int) $counts[2] ) {
			$out[] = array( 'id' => 'scan_medium', 'status' => 'warn', 'severity' => 'medium', 'title' => __( 'Scan findings to review', 'bastion-security' ), 'detail' => sprintf( _n( '%d medium issue from the last scan.', '%d medium issues from the last scan.', (int) $counts[2], 'bastion-security' ), (int) $counts[2] ), 'fix_url' => $scan, 'fix_label' => __( 'Review', 'bastion-security' ) );
		}
		$learning = 'learning' === Bastion_Settings::get( 'waf_mode' );
		$out[]    = array( 'id' => 'waf_mode', 'status' => $learning ? 'warn' : 'pass', 'severity' => 'medium', 'title' => __( 'Firewall blocks attacks', 'bastion-security' ), 'detail' => $learning ? __( 'The firewall is in learning mode: it only logs attacks. Switch to Protect once you have checked the log for false alarms.', 'bastion-security' ) : __( 'Attacks are blocked, not just logged.', 'bastion-security' ), 'fix_url' => admin_url( 'admin.php?page=bastion-firewall' ) );
		$mode  = Bastion_Comments::mode();
		$out[] = array( 'id' => 'comment_shield', 'status' => 'on' === $mode ? 'pass' : 'warn', 'severity' => 'off' === $mode ? 'medium' : 'low', 'title' => __( 'Comment spam is blocked', 'bastion-security' ), 'detail' => 'on' === $mode ? __( 'Bastion stops comment bots before anything is saved.', 'bastion-security' ) : ( 'log' === $mode ? __( 'The spam shield only watches. Turn it on to block bots.', 'bastion-security' ) : __( 'The comment spam shield is off.', 'bastion-security' ) ), 'fix_url' => admin_url( 'admin.php?page=bastion-comments' ) );
		$waiting = Bastion_Comments::counts()['pending'];
		$out[]   = array( 'id' => 'comment_backlog', 'status' => $waiting > 500 ? 'fail' : ( $waiting > 20 ? 'warn' : 'pass' ), 'severity' => $waiting > 500 ? 'high' : 'medium', 'title' => __( 'Comments are kept under control', 'bastion-security' ), 'detail' => $waiting > 20 ? sprintf( __( '%s comments are waiting for approval. Bastion can find the spam among them and clear it in one go.', 'bastion-security' ), number_format_i18n( $waiting ) ) : __( 'No pile of waiting comments.', 'bastion-security' ), 'fix_url' => admin_url( 'admin.php?page=bastion-comments#cleanup' ), 'fix_label' => __( 'Clean up', 'bastion-security' ) );
		return $out;
	}
}
