<?php
/**
 * WordPress side of the firewall: writes the config the early firewall reads, installs the
 * loaders, runs the deferred (cookie-verified) inspection, throttles 404 floods and imports
 * the firewall's log into the activity log.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Firewall {

	const MU_FILE      = 'bastion-waf-loader.php';
	const PREPEND_FILE = 'bastion-waf-prepend.php';
	const MARK_BEGIN   = 'BEGIN Bastion Security Firewall';
	const MARK_END     = 'END Bastion Security Firewall';

	public static function init() {
		// Earliest point where the login cookie can be verified (pluggable.php is loaded).
		add_action( 'plugins_loaded', array( __CLASS__, 'run_deferred' ), PHP_INT_MIN );
		add_action( 'template_redirect', array( __CLASS__, 'track_404' ), 1 );
		add_action( 'bastion_settings_updated', array( __CLASS__, 'write_config' ) );
	}

	public static function waf() {
		return Bastion_Waf::instance();
	}

	public static function storage() {
		return self::waf()->storage;
	}

	/* ======================================================== config / loaders */

	public static function build_config() {
		$s = Bastion_Settings::all();
		return array(
			'enabled'              => (bool) $s['waf_enabled'],
			'mode'                 => $s['waf_mode'],
			'ip_mode'              => $s['ip_mode'],
			'trusted_proxies'      => array_values( (array) $s['trusted_proxies'] ),
			'allowlist'            => array_values( (array) $s['ip_allowlist'] ),
			'blocklist'            => array_values( (array) $s['ip_blocklist'] ),
			'countries'            => array_values( (array) $s['country_block'] ),
			'country_scope'        => $s['country_scope'],
			'block_bad_ua'         => (bool) $s['waf_block_bad_ua'],
			'block_probes'         => (bool) $s['waf_block_probes'],
			'block_php_uploads'    => (bool) $s['waf_block_php_uploads'],
			'block_user_enum'      => (bool) $s['block_user_enum'],
			'xmlrpc_mode'          => $s['xmlrpc_mode'],
			'auto_block_threshold' => (int) $s['auto_block_threshold'],
			'auto_block_seconds'   => (int) $s['auto_block_minutes'] * 60,
			'rate_limit_rpm'       => (int) $s['rate_limit_rpm'],
			'rate_limit_seconds'   => (int) $s['rate_limit_minutes'] * 60,
			'disabled_rules'       => array_values( (array) $s['disabled_rules'] ),
			'param_allowlist'      => array_values( (array) $s['param_allowlist'] ),
			'generated'            => time(),
		);
	}

	public static function write_config() {
		$storage = self::storage();
		$storage->ensure_dir();
		$config = self::build_config();
		$ok     = $storage->write_php_array( 'config.php', $config );
		// Keep this request's engine in sync.
		self::waf()->config = $config;
		return $ok;
	}

	public static function disable_config() {
		$storage = self::storage();
		$config  = $storage->load_config();
		if ( $config ) {
			$config['enabled'] = false;
			$storage->write_php_array( 'config.php', $config );
		}
	}

	public static function install_mu_loader() {
		$dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		$bootstrap = BASTION_DIR . 'waf/bootstrap.php';
		$code      = "<?php\n/**\n * Plugin Name: Bastion Security — Firewall loader\n * Description: Starts the Bastion firewall before other plugins load. Managed by Bastion Security and removed when it is deactivated.\n */\n\n"
			. "defined( 'ABSPATH' ) || exit;\n\n"
			. "if ( ! defined( 'BASTION_WAF_DIR' ) ) {\n\tdefine( 'BASTION_WAF_DIR', WP_CONTENT_DIR . '/bastion-waf' );\n}\n"
			. "define( 'BASTION_WAF_MU', true );\n"
			. '$bastion_waf_bootstrap = ' . var_export( $bootstrap, true ) . ";\n"
			. "if ( is_file( \$bastion_waf_bootstrap ) ) {\n\tinclude_once \$bastion_waf_bootstrap;\n}\nunset( \$bastion_waf_bootstrap );\n";
		return false !== @file_put_contents( $dir . '/' . self::MU_FILE, $code );
	}

	public static function remove_mu_loader() {
		$dir  = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		$file = $dir . '/' . self::MU_FILE;
		if ( is_file( $file ) ) {
			@unlink( $file );
		}
	}

	/* ============================================== extended (prepend) mode */

	public static function status() {
		if ( ! Bastion_Settings::get( 'waf_enabled' ) ) {
			return 'disabled';
		}
		if ( defined( 'BASTION_WAF_PREPENDED' ) ) {
			return 'extended';
		}
		if ( get_option( 'bastion_prepend_installed' ) ) {
			$at = (int) get_option( 'bastion_prepend_installed_at' );
			if ( ! $at ) { // Installed by an older version: start the clock now.
				$at = time();
				update_option( 'bastion_prepend_installed_at', $at, false );
			}
			// Still not loaded after 10 minutes: this server ignores the method that was used.
			return time() - $at > self::STUCK_AFTER ? 'stuck' : 'pending';
		}
		return defined( 'BASTION_WAF_MU' ) ? 'standard' : 'basic';
	}

	/** Seconds after which extended mode that never loaded counts as not working on this server. */
	const STUCK_AFTER = 600;

	/** The ways of loading the firewall before WordPress, best guess for this server first. */
	public static function methods() {
		return 'htaccess' === self::server_method() ? array( 'htaccess', 'user_ini' ) : array( 'user_ini', 'htaccess' );
	}

	/** A method not tried on this site yet ('' when both were tried). */
	public static function untried_method() {
		$tried   = (array) get_option( 'bastion_prepend_tried', array() );
		$tried[] = (string) get_option( 'bastion_prepend_installed' );
		foreach ( self::methods() as $m ) {
			if ( ! in_array( $m, $tried, true ) ) {
				return $m;
			}
		}
		return '';
	}

	/** True when both methods were tried and the server applied neither. */
	public static function extended_unsupported() {
		return 'stuck' === self::status() && '' === self::untried_method();
	}

	public static function server_method() {
		$sapi = PHP_SAPI;
		$soft = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		if ( 'apache2handler' === $sapi || 'litespeed' === $sapi || false !== strpos( $soft, 'litespeed' ) ) {
			return 'htaccess';
		}
		return 'user_ini';
	}

	/**
	 * Run the firewall before WordPress via auto_prepend_file.
	 *
	 * @return true|WP_Error
	 */
	public static function install_prepend( $method = '' ) {
		$method  = in_array( $method, array( 'htaccess', 'user_ini' ), true ) ? $method : self::server_method();
		$current = (string) ini_get( 'auto_prepend_file' );
		$ours    = ABSPATH . self::PREPEND_FILE;
		if ( '' !== $current && realpath( $current ) !== realpath( $ours ) ) {
			return new WP_Error( 'bastion_prepend_taken', sprintf( __( 'Another tool already uses auto_prepend_file (%s). Remove it first (for example another firewall plugin).', 'bastion-security' ), $current ) );
		}
		$bootstrap = BASTION_DIR . 'waf/bootstrap.php';
		$code      = "<?php\n// Bastion Security firewall. Loaded before WordPress via auto_prepend_file.\n// To disable in an emergency, delete this file.\n"
			. 'if ( is_file( ' . var_export( $bootstrap, true ) . " ) ) {\n"
			. "\tif ( ! defined( 'BASTION_WAF_DIR' ) ) {\n\t\tdefine( 'BASTION_WAF_DIR', " . var_export( BASTION_WAF_DIR, true ) . " );\n\t}\n"
			. "\tdefine( 'BASTION_WAF_PREPENDED', true );\n"
			. "\tinclude_once " . var_export( $bootstrap, true ) . ";\n}\n";
		if ( false === @file_put_contents( $ours, $code ) ) {
			return new WP_Error( 'bastion_prepend_write', __( 'Could not write the firewall file to the site root. Check file permissions.', 'bastion-security' ) );
		}

		// Switching method: take our rule out of the other file first.
		self::write_block( ABSPATH . ( 'htaccess' === $method ? '.user.ini' : '.htaccess' ), 'htaccess' === $method ? '; ' : '# ', array() );
		if ( 'htaccess' === $method ) {
			$lines = array(
				'<IfModule mod_php.c>',
				'php_value auto_prepend_file ' . self::quote( $ours ),
				'</IfModule>',
				'<IfModule mod_php7.c>',
				'php_value auto_prepend_file ' . self::quote( $ours ),
				'</IfModule>',
				'<IfModule lsapi_module>',
				'php_value auto_prepend_file ' . self::quote( $ours ),
				'</IfModule>',
			);
			$ok = self::write_block( ABSPATH . '.htaccess', '# ', $lines );
		} else {
			$ok = self::write_block( ABSPATH . '.user.ini', '; ', array( 'auto_prepend_file = ' . self::quote( $ours ) ) );
		}
		if ( ! $ok ) {
			@unlink( $ours );
			return new WP_Error( 'bastion_prepend_config', __( 'Could not update the server configuration file. Check file permissions.', 'bastion-security' ) );
		}
		// Remember every way tried here, including the one in place before (older versions kept no list).
		$tried = array_merge( (array) get_option( 'bastion_prepend_tried', array() ), array( (string) get_option( 'bastion_prepend_installed' ), $method ) );
		update_option( 'bastion_prepend_installed', $method, false );
		update_option( 'bastion_prepend_installed_at', time(), false );
		update_option( 'bastion_prepend_tried', array_values( array_filter( array_unique( $tried ) ) ), false );
		return true;
	}

	public static function uninstall_prepend() {
		self::write_block( ABSPATH . '.htaccess', '# ', array() );
		self::write_block( ABSPATH . '.user.ini', '; ', array() );
		delete_option( 'bastion_prepend_installed' );
		delete_option( 'bastion_prepend_installed_at' );
		delete_option( 'bastion_prepend_tried' ); // Removing it by hand starts over.
		// The prepend file stays until PHP stops loading it (.user.ini is cached for ~5 minutes);
		// it is harmless because it only loads the firewall when the plugin files exist.
		wp_schedule_single_event( time() + 600, 'bastion_remove_prepend_file' );
	}

	public static function remove_prepend_file() {
		if ( ! get_option( 'bastion_prepend_installed' ) && ! defined( 'BASTION_WAF_PREPENDED' ) ) {
			@unlink( ABSPATH . self::PREPEND_FILE );
		}
	}

	private static function quote( $path ) {
		return "'" . str_replace( "'", '', $path ) . "'";
	}

	/** Replace (or remove, with empty $lines) our marked block inside a config file. */
	private static function write_block( $file, $comment, array $lines ) {
		$existing = is_file( $file ) ? (string) file_get_contents( $file ) : '';
		$pattern  = '~\n?' . preg_quote( $comment . self::MARK_BEGIN, '~' ) . '.*?' . preg_quote( $comment . self::MARK_END, '~' ) . '\n?~s';
		$clean    = preg_replace( $pattern, "\n", $existing );
		$clean    = trim( (string) $clean, "\n" );
		if ( $lines ) {
			$block = $comment . self::MARK_BEGIN . "\n" . implode( "\n", $lines ) . "\n" . $comment . self::MARK_END;
			// Prepend so it applies before other rules.
			$clean = $block . ( '' !== $clean ? "\n\n" . $clean : '' );
		}
		if ( '' === $clean ) {
			// Our block was the only content: remove the file instead of leaving it empty.
			return ! is_file( $file ) || @unlink( $file );
		}
		if ( ( is_file( $file ) && ! is_writable( $file ) ) || ( ! is_file( $file ) && ! is_writable( dirname( $file ) ) ) ) {
			return false;
		}
		return false !== file_put_contents( $file, $clean . "\n", LOCK_EX );
	}

	/* ================================================================ runtime */

	public static function run_deferred() {
		$waf = self::waf();
		if ( ! $waf->deferred ) {
			return;
		}
		$user_id = (int) wp_validate_auth_cookie( '', 'logged_in' );
		$admin   = $user_id && ( user_can( $user_id, 'manage_options' ) || is_super_admin( $user_id ) );
		$html    = $user_id && user_can( $user_id, 'unfiltered_html' );
		$waf->run_deferred( $user_id, $admin, $html );
	}

	public static function track_404() {
		$limit = (int) Bastion_Settings::get( 'rate_404_per_min' );
		if ( $limit <= 0 || ! is_404() || is_user_logged_in() || ! Bastion_Settings::get( 'waf_enabled' ) ) {
			return;
		}
		$waf = self::waf();
		if ( $waf->allowlisted ) {
			return;
		}
		$n = $waf->storage->hit( '404:' . $waf->ip, 60 );
		if ( $n === $limit + 1 && ! $waf->only_learning( 'rate_404', sprintf( '%d not-found requests in one minute (scanning)', $n ) ) ) {
			$waf->storage->add_block( $waf->ip, 15 * MINUTE_IN_SECONDS, sprintf( 'Too many 404s (%d per minute)', $n ), 'all' );
			Bastion_Events::log( 'rate_404', sprintf( 'Blocked for 15 minutes after %d not-found requests in one minute (scanning)', $n ), array( 'severity' => Bastion_Events::MEDIUM, 'data' => array( 'uri' => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' ) ) );
		}
	}

	/** Move queued firewall log lines into the activity log table. */
	public static function ingest() {
		$severity = array(
			'waf'        => Bastion_Events::HIGH,
			'auto_block' => Bastion_Events::HIGH,
			'probe'      => Bastion_Events::MEDIUM,
			'bad_bot'    => Bastion_Events::MEDIUM,
			'rate_limit' => Bastion_Events::MEDIUM,
			'learning'   => Bastion_Events::INFO,
		);
		$rows = self::storage()->drain_log();
		foreach ( array_slice( $rows, -5000 ) as $r ) {
			$type = isset( $r['type'] ) ? sanitize_key( $r['type'] ) : 'waf';
			$data = array_intersect_key( $r, array_flip( array( 'id', 'method', 'uri', 'ua', 'cc', 'rule', 'cat', 'param', 'match' ) ) );
			Bastion_Events::log(
				$type,
				isset( $r['msg'] ) ? (string) $r['msg'] : '',
				array(
					'time'     => isset( $r['t'] ) ? (int) $r['t'] : time(),
					'ip'       => isset( $r['ip'] ) ? (string) $r['ip'] : '',
					'severity' => isset( $severity[ $type ] ) ? $severity[ $type ] : Bastion_Events::LOW,
					'user_id'  => 0,
					'username' => '',
					'data'     => $data,
				)
			);
		}
		return count( $rows );
	}

	/* ============================================================ blocks API */

	public static function block_ip( $ip, $minutes, $reason ) {
		$ip = Bastion_IP::normalize( $ip );
		if ( ! Bastion_IP::is_valid( $ip ) ) {
			return false;
		}
		return self::storage()->add_block( $ip, (int) $minutes * 60, $reason, 'all' );
	}

	public static function unblock_ip( $ip ) {
		$storage = self::storage();
		$storage->remove_block( $ip );
		$storage->reset_counter( 'lf:' . $ip, (int) Bastion_Settings::get( 'login_window_minutes' ) * 60 );
		$storage->reset_counter( 'atk:' . $ip, 600 );
		$storage->reset_counter( 'req:' . $ip, 60 );
		$storage->reset_counter( '404:' . $ip, 60 );
	}

	/** Active blocks, newest first. */
	public static function active_blocks() {
		$now  = time();
		$list = array();
		foreach ( self::storage()->get_blocks() as $ip => $b ) {
			if ( empty( $b['until'] ) || $b['until'] > $now ) {
				$b['ip'] = $ip;
				$list[]  = $b;
			}
		}
		usort(
			$list,
			function ( $a, $b ) {
				return $b['created'] - $a['created'];
			}
		);
		return $list;
	}
}
