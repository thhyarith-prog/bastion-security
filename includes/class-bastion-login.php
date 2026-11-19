<?php
/**
 * Login security: brute-force lockouts, username protection, XML-RPC and REST hardening,
 * password policy with breach checking, and new-IP sign-in alerts.
 *
 * Lockouts are stored in the firewall's block list with scope "login", so a locked-out IP
 * is rejected before WordPress even loads on the next attempt.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Login {

	const GENERIC_CODES = array( 'invalid_username', 'incorrect_password', 'invalid_email' );

	public static function init() {
		add_filter( 'authenticate', array( __CLASS__, 'enforce_lockout' ), 99, 3 );
		add_filter( 'authenticate', array( __CLASS__, 'generic_errors' ), 100, 3 );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_failed' ), 10, 2 );
		add_action( 'wp_login', array( __CLASS__, 'on_success' ), 10, 2 );
		add_action( 'lostpassword_post', array( __CLASS__, 'limit_lostpassword' ), 10, 1 );

		// Username discovery.
		if ( Bastion_Settings::get( 'block_user_enum' ) ) {
			add_filter( 'rest_endpoints', array( __CLASS__, 'hide_user_endpoints' ) );
			add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'remove_user_sitemap' ), 10, 2 );
			add_filter( 'oembed_response_data', array( __CLASS__, 'strip_oembed_author' ) );
		}

		// XML-RPC.
		$xmlrpc = Bastion_Settings::get( 'xmlrpc_mode' );
		if ( 'restrict' === $xmlrpc ) {
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'restrict_xmlrpc' ) );
			add_filter( 'wp_headers', array( __CLASS__, 'remove_pingback_header' ) );
		} elseif ( 'disable' === $xmlrpc ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			add_filter( 'wp_headers', array( __CLASS__, 'remove_pingback_header' ) );
			remove_action( 'wp_head', 'rsd_link' );
		}

		if ( Bastion_Settings::get( 'disable_app_passwords' ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}

		// Password policy.
		add_action( 'user_profile_update_errors', array( __CLASS__, 'check_profile_password' ), 10, 3 );
		add_action( 'validate_password_reset', array( __CLASS__, 'check_reset_password' ), 10, 2 );
	}

	private static function waf() {
		return Bastion_Waf::instance();
	}

	/* ============================================================= lockouts */

	public static function enforce_lockout( $user, $username, $password ) {
		$waf = self::waf();
		if ( $waf->allowlisted || '' === (string) $username ) {
			return $user;
		}
		$block = $waf->storage->get_block( $waf->ip );
		if ( $block ) {
			return new WP_Error( 'bastion_locked_out', self::lockout_message( $block ) );
		}
		// Login attempt as a well-known default name that does not exist here: instant lockout.
		$deny = array_map( 'strtolower', (array) Bastion_Settings::get( 'login_block_usernames' ) );
		$name = strtolower( trim( (string) $username ) );
		if ( in_array( $name, $deny, true ) && ! username_exists( $username ) && ! email_exists( $username ) ) {
			self::lock( $waf->ip, sprintf( 'Tried to sign in as "%s"', $username ), (string) $username );
			return new WP_Error( 'bastion_locked_out', self::lockout_message( $waf->storage->get_block( $waf->ip ) ) );
		}
		return $user;
	}

	public static function generic_errors( $user, $username, $password ) {
		if ( ! Bastion_Settings::get( 'login_generic_errors' ) || ! is_wp_error( $user ) ) {
			return $user;
		}
		if ( array_intersect( $user->get_error_codes(), self::GENERIC_CODES ) ) {
			$lost = wp_lostpassword_url();
			return new WP_Error(
				'bastion_invalid_login',
				sprintf(
					/* translators: %s: lost password URL */
					__( '<strong>Error:</strong> The username or password is incorrect. <a href="%s">Lost your password?</a>', 'bastion-security' ),
					esc_url( $lost )
				)
			);
		}
		return $user;
	}

	public static function on_failed( $username, $error = null ) {
		$waf = self::waf();
		if ( $waf->allowlisted ) {
			return;
		}
		if ( is_wp_error( $error ) && in_array( 'bastion_locked_out', $error->get_error_codes(), true ) ) {
			return; // Already locked out; do not count again.
		}
		$exists = username_exists( $username ) || email_exists( $username );
		$window = max( 1, (int) Bastion_Settings::get( 'login_window_minutes' ) ) * 60;
		// Guessing usernames that do not exist counts double: it is never a typo-prone real user.
		$count = $waf->storage->hit( 'lf:' . $waf->ip, $window, $exists ? 1 : 2 );
		$max   = max( 1, (int) Bastion_Settings::get( 'login_max_attempts' ) );

		Bastion_Events::log(
			'login_failed',
			sprintf( 'Failed login for "%s"%s (%d/%d)', $username, $exists ? '' : ' (no such user)', min( $count, $max ), $max ),
			array( 'severity' => Bastion_Events::LOW, 'user_id' => 0, 'username' => (string) $username )
		);

		if ( $count >= $max ) {
			self::lock( $waf->ip, sprintf( '%d failed logins', $count ), (string) $username );
		}
	}

	/** Add a login-scope lockout, doubling the duration for repeat offenders. */
	public static function lock( $ip, $reason, $username = '' ) {
		$storage = self::waf()->storage;
		$minutes = max( 1, (int) Bastion_Settings::get( 'login_lockout_minutes' ) );
		if ( Bastion_Settings::get( 'login_progressive' ) ) {
			$strikes = $storage->hit( 'lo:' . $ip, DAY_IN_SECONDS );
			$minutes = min( 1440, $minutes * (int) pow( 2, min( 10, $strikes - 1 ) ) );
		}
		$storage->add_block( $ip, $minutes * 60, $reason, 'login' );
		$storage->reset_counter( 'lf:' . $ip, max( 1, (int) Bastion_Settings::get( 'login_window_minutes' ) ) * 60 );

		Bastion_Events::log(
			'lockout_added',
			sprintf( 'Locked out of login for %d minutes: %s', $minutes, $reason ),
			array( 'severity' => Bastion_Events::MEDIUM, 'ip' => $ip, 'user_id' => 0, 'username' => $username )
		);
		if ( Bastion_Settings::get( 'alert_lockouts' ) ) {
			Bastion_Events::alert(
				'lockouts',
				__( 'Login lockout', 'bastion-security' ),
				sprintf( "IP %s was locked out of login for %d minutes.\nReason: %s\nUsername tried: %s\n\nFurther lockout emails are paused for an hour.", $ip, $minutes, $reason, $username ),
				HOUR_IN_SECONDS
			);
		}
	}

	private static function lockout_message( $block ) {
		$until = $block && ! empty( $block['until'] ) ? $block['until'] : 0;
		$mins  = $until ? max( 1, (int) ceil( ( $until - time() ) / 60 ) ) : 0;
		return $mins
			? sprintf( __( '<strong>Locked out:</strong> too many failed login attempts. Try again in %d minutes.', 'bastion-security' ), $mins )
			: __( '<strong>Locked out:</strong> login from your network is blocked.', 'bastion-security' );
	}

	public static function on_success( $login, $user ) {
		$waf = self::waf();
		$waf->storage->reset_counter( 'lf:' . $waf->ip, max( 1, (int) Bastion_Settings::get( 'login_window_minutes' ) ) * 60 );
		Bastion_Events::log( 'login_success', sprintf( '"%s" signed in', $login ), array( 'user_id' => $user->ID, 'username' => $login ) );

		// Remember recent IPs; alert administrators about sign-ins from somewhere new.
		$known = (array) get_user_meta( $user->ID, '_bastion_known_ips', true );
		$ip    = $waf->ip;
		if ( ! in_array( $ip, $known, true ) ) {
			if ( $known && user_can( $user, 'manage_options' ) && Bastion_Settings::get( 'alert_admin_new_ip' ) ) {
				$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
				$cc = $waf->country();
				Bastion_Events::alert(
					'newip_' . $user->ID . '_' . $ip,
					sprintf( __( 'Administrator "%s" signed in from a new IP', 'bastion-security' ), $login ),
					sprintf(
						"User: %s\nIP: %s%s\nBrowser: %s\nTime: %s\n\n%s",
						$login,
						$ip,
						$cc ? " ($cc)" : '',
						$ua,
						wp_date( 'Y-m-d H:i:s T' ),
						__( 'If this was not you, change the password immediately and sign out all sessions from the user profile.', 'bastion-security' )
					),
					DAY_IN_SECONDS
				);
			}
			array_unshift( $known, $ip );
			update_user_meta( $user->ID, '_bastion_known_ips', array_slice( array_values( array_filter( $known ) ), 0, 15 ) );
		}
	}

	public static function limit_lostpassword( $errors ) {
		$limit = (int) Bastion_Settings::get( 'lostpassword_limit' );
		$waf   = self::waf();
		if ( $limit <= 0 || $waf->allowlisted ) {
			return;
		}
		$n = $waf->storage->hit( 'lp:' . $waf->ip, 15 * MINUTE_IN_SECONDS );
		if ( $n > $limit ) {
			if ( $n === $limit + 1 ) {
				Bastion_Events::log( 'password_reset_limit', 'Too many password reset requests', array( 'severity' => Bastion_Events::LOW ) );
			}
			$errors->add( 'bastion_too_many', __( '<strong>Error:</strong> Too many password reset requests. Please wait 15 minutes.', 'bastion-security' ) );
		}
	}

	/* ===================================================== enumeration / xmlrpc */

	public static function hide_user_endpoints( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	public static function remove_user_sitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	public static function strip_oembed_author( $data ) {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	public static function restrict_xmlrpc( $methods ) {
		unset( $methods['system.multicall'], $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'], $methods['system.listMethods'] );
		return $methods;
	}

	public static function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/* ======================================================== password policy */

	public static function check_profile_password( $errors, $update, $user ) {
		if ( empty( $user->user_pass ) ) {
			return;
		}
		$roles = array();
		if ( ! empty( $user->role ) ) {
			$roles[] = $user->role;
		}
		if ( $update && ! empty( $user->ID ) ) {
			$existing = get_userdata( $user->ID );
			if ( $existing ) {
				$roles = array_merge( $roles, (array) $existing->roles );
			}
		}
		$login = ! empty( $user->user_login ) ? $user->user_login : '';
		self::validate_password( $errors, $user->user_pass, $roles, $login );
	}

	public static function check_reset_password( $errors, $user ) {
		if ( ! empty( $_POST['pass1'] ) && $user instanceof WP_User ) { // phpcs:ignore WordPress.Security.NonceVerification
			self::validate_password( $errors, wp_unslash( $_POST['pass1'] ), (array) $user->roles, $user->user_login ); // phpcs:ignore
		}
	}

	private static function validate_password( $errors, $password, array $roles, $login ) {
		$password = (string) $password;
		if ( array_intersect( $roles, (array) Bastion_Settings::get( 'password_roles' ) ) ) {
			$min = (int) Bastion_Settings::get( 'password_min_length' );
			if ( strlen( $password ) < $min ) {
				$errors->add( 'bastion_pass_short', sprintf( __( '<strong>Error:</strong> Passwords for this role must be at least %d characters.', 'bastion-security' ), $min ) );
				return;
			}
			if ( $login && false !== stripos( $password, $login ) ) {
				$errors->add( 'bastion_pass_login', __( '<strong>Error:</strong> The password must not contain the username.', 'bastion-security' ) );
				return;
			}
			if ( count( array_unique( str_split( $password ) ) ) < 5 ) {
				$errors->add( 'bastion_pass_simple', __( '<strong>Error:</strong> The password is too simple.', 'bastion-security' ) );
				return;
			}
		}
		if ( Bastion_Settings::get( 'password_breach_check' ) ) {
			$seen = self::pwned_count( $password );
			if ( $seen > 0 ) {
				$errors->add(
					'bastion_pass_pwned',
					sprintf(
						/* translators: %s: number of times seen */
						__( '<strong>Error:</strong> This password has appeared %s times in known data breaches. Choose a different one.', 'bastion-security' ),
						number_format_i18n( $seen )
					)
				);
			}
		}
	}

	/**
	 * Have I Been Pwned range query (k-anonymity). Only a 5-character hash prefix is sent.
	 *
	 * @return int Times seen; 0 if not found or the service is unreachable (fails open).
	 */
	public static function pwned_count( $password ) {
		$hash   = strtoupper( sha1( $password ) );
		$prefix = substr( $hash, 0, 5 );
		$suffix = substr( $hash, 5 );
		$res    = wp_remote_get(
			'https://api.pwnedpasswords.com/range/' . $prefix,
			array(
				'timeout'    => 5,
				'headers'    => array( 'Add-Padding' => 'true' ),
				'user-agent' => 'Bastion-Security-WordPress',
			)
		);
		if ( is_wp_error( $res ) || 200 !== wp_remote_retrieve_response_code( $res ) ) {
			return 0;
		}
		foreach ( explode( "\n", wp_remote_retrieve_body( $res ) ) as $line ) {
			$parts = explode( ':', trim( $line ) );
			if ( 2 === count( $parts ) && hash_equals( $suffix, $parts[0] ) ) {
				return (int) $parts[1];
			}
		}
		return 0;
	}
}
