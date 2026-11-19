<?php
/**
 * Two-factor authentication (TOTP authenticator apps + one-time backup codes).
 *
 * Flow: after the password is verified (authenticate filter, last priority) the user is sent
 * to wp-login.php?action=bastion_2fa with a short-lived single-use token. No auth cookie is
 * issued until the second factor is verified. Works with any login form that uses wp_signon
 * (wp-login.php, WooCommerce, page builders).
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Two_Factor {

	const META_SECRET  = '_bastion_tfa_secret';
	const META_PENDING = '_bastion_tfa_pending';
	const META_LAST    = '_bastion_tfa_last';
	const META_BACKUP  = '_bastion_tfa_backup';
	const META_LOGIN   = '_bastion_tfa_login';
	const META_SINCE   = '_bastion_tfa_required_since';
	const TOKEN_TTL    = 600;
	const MAX_TRIES    = 5;

	public static function init() {
		add_filter( 'authenticate', array( __CLASS__, 'intercept' ), 9999, 3 );
		add_action( 'login_form_bastion_2fa', array( __CLASS__, 'login_page' ) );
		add_filter( 'login_message', array( __CLASS__, 'expired_message' ) );

		add_action( 'show_user_profile', array( __CLASS__, 'profile_section' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'profile_section' ) );
		add_action( 'admin_init', array( __CLASS__, 'enforce' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );

		foreach ( array( 'begin', 'confirm', 'disable', 'regen' ) as $a ) {
			add_action( 'wp_ajax_bastion_tfa_' . $a, array( __CLASS__, 'ajax_' . $a ) );
		}
	}

	/* ================================================================ state */

	public static function secret( $user_id ) {
		$stored = get_user_meta( $user_id, self::META_SECRET, true );
		if ( ! $stored ) {
			return false;
		}
		return Bastion_TOTP::decrypt( $stored );
	}

	public static function is_enabled( $user_id ) {
		return false !== self::secret( $user_id );
	}

	/** Secret stored but unreadable (e.g. wp-config salts were rotated). */
	public static function is_broken( $user_id ) {
		return get_user_meta( $user_id, self::META_SECRET, true ) && ! self::is_enabled( $user_id );
	}

	public static function is_required( $user ) {
		$user = $user instanceof WP_User ? $user : get_userdata( $user );
		return $user && array_intersect( (array) $user->roles, (array) Bastion_Settings::get( 'tfa_required_roles' ) );
	}

	/* ========================================================== login flow */

	public static function intercept( $user, $username, $password ) {
		if ( ! $user instanceof WP_User || ( '' === (string) $username && '' === (string) $password ) ) {
			return $user;
		}
		if ( ! self::is_enabled( $user->ID ) ) {
			return $user;
		}
		if ( did_action( 'application_password_did_authenticate' ) ) {
			return $user; // Application passwords are designed for API clients that cannot do 2FA.
		}
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return new WP_Error( 'bastion_2fa_required', __( 'This account uses two-factor authentication. Use an application password for API access.', 'bastion-security' ) );
		}
		if ( self::device_remembered( $user ) ) {
			return $user;
		}

		$token = bin2hex( random_bytes( 24 ) );
		// phpcs:disable WordPress.Security.NonceVerification
		$redirect = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : '';
		if ( '' === $redirect && ! empty( $_SERVER['HTTP_REFERER'] ) && false === strpos( wp_unslash( $_SERVER['HTTP_REFERER'] ), 'wp-login.php' ) ) {
			$redirect = wp_unslash( $_SERVER['HTTP_REFERER'] );
		}
		update_user_meta(
			$user->ID,
			self::META_LOGIN,
			array(
				'hash'     => hash( 'sha256', $token ),
				'expires'  => time() + self::TOKEN_TTL,
				'remember' => ! empty( $_POST['rememberme'] ),
				'redirect' => esc_url_raw( $redirect ),
				'tries'    => 0,
			)
		);
		// phpcs:enable
		$url = add_query_arg(
			array(
				'action' => 'bastion_2fa',
				'u'      => $user->ID,
				't'      => $token,
			),
			site_url( 'wp-login.php', 'login_post' )
		);
		if ( wp_doing_ajax() ) {
			return new WP_Error( 'bastion_2fa_required', sprintf( __( 'Two-factor authentication required. <a href="%s">Continue</a>', 'bastion-security' ), esc_url( $url ) ) );
		}
		wp_safe_redirect( $url );
		exit;
	}

	public static function expired_message( $message ) {
		if ( isset( $_GET['bastion_2fa'] ) && 'expired' === $_GET['bastion_2fa'] ) { // phpcs:ignore
			$message .= '<div id="login_error" class="notice notice-error"><p>' . esc_html__( 'Your two-factor session expired or had too many wrong codes. Please sign in again.', 'bastion-security' ) . '</p></div>';
		}
		return $message;
	}

	private static function restart_login() {
		wp_safe_redirect( add_query_arg( 'bastion_2fa', 'expired', wp_login_url() ) );
		exit;
	}

	public static function login_page() {
		// phpcs:disable WordPress.Security.NonceVerification
		$uid   = isset( $_REQUEST['u'] ) ? absint( $_REQUEST['u'] ) : 0;
		$token = isset( $_REQUEST['t'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['t'] ) ) : '';
		// phpcs:enable
		$user = $uid ? get_userdata( $uid ) : false;
		$data = $user ? get_user_meta( $uid, self::META_LOGIN, true ) : false;

		if ( ! $user || ! is_array( $data ) || $data['expires'] < time() || ! hash_equals( $data['hash'], hash( 'sha256', $token ) ) ) {
			self::restart_login();
		}

		$errors = new WP_Error();
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			check_admin_referer( 'bastion_2fa_' . $uid );
			$code   = isset( $_POST['bastion_code'] ) ? sanitize_text_field( wp_unslash( $_POST['bastion_code'] ) ) : '';
			$method = self::verify_code( $user, $code );
			if ( $method ) {
				delete_user_meta( $uid, self::META_LOGIN );
				wp_set_auth_cookie( $uid, ! empty( $data['remember'] ), is_ssl() );
				if ( ! empty( $_POST['bastion_remember_device'] ) ) {
					self::remember_device( $user );
				}
				Bastion_Events::log( 'tfa_success', sprintf( '"%s" passed two-factor (%s)', $user->user_login, 'backup' === $method ? 'backup code' : 'authenticator' ), array( 'user_id' => $uid, 'username' => $user->user_login ) );
				if ( 'backup' === $method ) {
					$left = count( (array) get_user_meta( $uid, self::META_BACKUP, true ) );
					Bastion_Events::log( 'tfa_success', sprintf( 'Backup code used; %d left', $left ), array( 'severity' => Bastion_Events::LOW, 'user_id' => $uid, 'username' => $user->user_login ) );
				}
				do_action( 'wp_login', $user->user_login, $user );

				$requested = $data['redirect'];
				$redirect  = $requested ? $requested : admin_url();
				$redirect  = apply_filters( 'login_redirect', $redirect, $requested, $user );
				if ( ( empty( $redirect ) || admin_url() === $redirect ) && ! $user->has_cap( 'edit_posts' ) ) {
					$redirect = admin_url( 'profile.php' );
				}
				wp_safe_redirect( $redirect );
				exit;
			}

			$data['tries'] = (int) $data['tries'] + 1;
			if ( $data['tries'] >= self::MAX_TRIES ) {
				delete_user_meta( $uid, self::META_LOGIN );
				Bastion_Events::log( 'tfa_failed', sprintf( 'Too many wrong two-factor codes for "%s"', $user->user_login ), array( 'severity' => Bastion_Events::MEDIUM, 'user_id' => 0, 'username' => $user->user_login ) );
				do_action( 'wp_login_failed', $user->user_login, new WP_Error( 'bastion_2fa_failed', 'Two-factor failed' ) );
				self::restart_login();
			}
			update_user_meta( $uid, self::META_LOGIN, $data );
			Bastion_Events::log( 'tfa_failed', sprintf( 'Wrong two-factor code for "%s"', $user->user_login ), array( 'severity' => Bastion_Events::LOW, 'user_id' => 0, 'username' => $user->user_login ) );
			$errors->add( 'bastion_bad_code', __( '<strong>Error:</strong> That code is not valid. Check the time on your phone and try again.', 'bastion-security' ) );
		}

		$days   = (int) Bastion_Settings::get( 'tfa_remember_days' );
		$action = add_query_arg(
			array(
				'action' => 'bastion_2fa',
				'u'      => $uid,
				't'      => $token,
			),
			site_url( 'wp-login.php', 'login_post' )
		);

		login_header( __( 'Two-factor authentication', 'bastion-security' ), '', $errors );
		?>
		<form name="bastion2fa" id="loginform" action="<?php echo esc_url( $action ); ?>" method="post" autocomplete="off">
			<p class="message" style="margin-bottom:16px"><?php esc_html_e( 'Enter the 6-digit code from your authenticator app, or one of your backup codes.', 'bastion-security' ); ?></p>
			<p>
				<label for="bastion_code"><?php esc_html_e( 'Authentication code', 'bastion-security' ); ?></label>
				<input type="text" name="bastion_code" id="bastion_code" class="input" value="" size="20" autocomplete="one-time-code" inputmode="numeric" autofocus required style="font-size:24px;letter-spacing:.2em;text-align:center" />
			</p>
			<?php if ( $days > 0 ) : ?>
				<p class="forgetmenot"><label><input name="bastion_remember_device" type="checkbox" value="1" /> <?php echo esc_html( sprintf( _n( 'Trust this device for %d day', 'Trust this device for %d days', $days, 'bastion-security' ), $days ) ); ?></label></p>
			<?php endif; ?>
			<?php wp_nonce_field( 'bastion_2fa_' . $uid ); ?>
			<p class="submit"><input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'bastion-security' ); ?>" /></p>
		</form>
		<p id="nav"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( '← Back to sign in', 'bastion-security' ); ?></a></p>
		<?php
		login_footer( 'bastion_code' );
		exit;
	}

	/**
	 * @return string|false "totp", "backup" or false.
	 */
	public static function verify_code( WP_User $user, $code ) {
		$secret = self::secret( $user->ID );
		if ( false === $secret ) {
			return false;
		}
		$digits = preg_replace( '/\s+/', '', (string) $code );
		if ( preg_match( '/^\d{6}$/', $digits ) ) {
			$last    = (int) get_user_meta( $user->ID, self::META_LAST, true );
			$counter = Bastion_TOTP::verify( $secret, $digits, $last );
			if ( false !== $counter ) {
				update_user_meta( $user->ID, self::META_LAST, $counter );
				return 'totp';
			}
			return false;
		}
		$normalized = strtolower( preg_replace( '/[^a-z0-9]/i', '', (string) $code ) );
		if ( strlen( $normalized ) !== 10 ) {
			return false;
		}
		$codes = (array) get_user_meta( $user->ID, self::META_BACKUP, true );
		foreach ( $codes as $i => $hash ) {
			if ( wp_check_password( $normalized, $hash ) ) {
				unset( $codes[ $i ] );
				update_user_meta( $user->ID, self::META_BACKUP, array_values( $codes ) );
				return 'backup';
			}
		}
		return false;
	}

	/* ================================================== remember this device */

	private static function device_cookie_name() {
		return 'bastion_tfa_device_' . COOKIEHASH;
	}

	private static function device_mac( WP_User $user, $expires ) {
		$secret_fingerprint = md5( (string) get_user_meta( $user->ID, self::META_SECRET, true ) );
		return hash_hmac( 'sha256', $user->ID . '|' . $expires . '|' . substr( $user->user_pass, 8, 4 ) . '|' . $secret_fingerprint, wp_salt( 'auth' ) );
	}

	private static function remember_device( WP_User $user ) {
		$days = (int) Bastion_Settings::get( 'tfa_remember_days' );
		if ( $days <= 0 ) {
			return;
		}
		$expires = time() + $days * DAY_IN_SECONDS;
		$value   = $user->ID . '|' . $expires . '|' . self::device_mac( $user, $expires );
		setcookie( self::device_cookie_name(), $value, array(
			'expires'  => $expires,
			'path'     => COOKIEPATH ? COOKIEPATH : '/',
			'domain'   => COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		) );
	}

	private static function device_remembered( WP_User $user ) {
		$name = self::device_cookie_name();
		if ( (int) Bastion_Settings::get( 'tfa_remember_days' ) <= 0 || empty( $_COOKIE[ $name ] ) ) {
			return false;
		}
		$parts = explode( '|', sanitize_text_field( wp_unslash( $_COOKIE[ $name ] ) ) );
		if ( 3 !== count( $parts ) || (int) $parts[0] !== $user->ID || (int) $parts[1] < time() ) {
			return false;
		}
		return hash_equals( self::device_mac( $user, (int) $parts[1] ), $parts[2] );
	}

	/* ============================================================ backups */

	private static function new_backup_codes( $user_id ) {
		$plain  = array();
		$hashes = array();
		$chars  = 'abcdefghjkmnpqrstuvwxyz23456789';
		for ( $i = 0; $i < 10; $i++ ) {
			$code = '';
			for ( $j = 0; $j < 10; $j++ ) {
				$code .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
			}
			$plain[]  = substr( $code, 0, 5 ) . '-' . substr( $code, 5 );
			$hashes[] = wp_hash_password( $code );
		}
		update_user_meta( $user_id, self::META_BACKUP, $hashes );
		return $plain;
	}

	/* ============================================================= profile UI */

	public static function profile_section( $user ) {
		$self    = get_current_user_id() === $user->ID;
		$enabled = self::is_enabled( $user->ID );
		if ( ! $self && ! $enabled ) {
			if ( current_user_can( 'edit_user', $user->ID ) ) {
				echo '<h2 id="bastion-2fa">' . esc_html__( 'Two-factor authentication', 'bastion-security' ) . '</h2><p>' . esc_html__( 'Not set up. Only the user can enable it from their own profile.', 'bastion-security' ) . '</p>';
			}
			return;
		}
		$left = count( (array) get_user_meta( $user->ID, self::META_BACKUP, true ) );
		?>
		<h2 id="bastion-2fa"><?php esc_html_e( 'Two-factor authentication', 'bastion-security' ); ?></h2>
		<div class="bastion-tfa" data-user="<?php echo (int) $user->ID; ?>" data-self="<?php echo $self ? '1' : '0'; ?>" data-nonce="<?php echo esc_attr( wp_create_nonce( 'bastion_tfa' ) ); ?>">
			<?php if ( $enabled ) : ?>
				<p class="bastion-tfa-status is-on"><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Enabled. A code from the authenticator app is required at every sign-in.', 'bastion-security' ); ?></p>
				<p class="description"><?php echo esc_html( sprintf( _n( '%d backup code left.', '%d backup codes left.', $left, 'bastion-security' ), $left ) ); ?></p>
				<?php if ( $self ) : ?>
					<p><input type="text" class="regular-text bastion-tfa-code" placeholder="<?php esc_attr_e( 'Current 6-digit code', 'bastion-security' ); ?>" inputmode="numeric" autocomplete="one-time-code" style="max-width:200px"></p>
				<?php endif; ?>
				<p>
					<?php if ( $self ) : ?><button type="button" class="button" data-tfa="regen"><?php esc_html_e( 'New backup codes', 'bastion-security' ); ?></button><?php endif; ?>
					<button type="button" class="button button-link-delete" data-tfa="disable"><?php esc_html_e( 'Turn off two-factor', 'bastion-security' ); ?></button>
				</p>
			<?php else : ?>
				<?php if ( self::is_broken( $user->ID ) ) : ?>
					<p class="notice notice-warning inline" style="padding:8px 12px"><?php esc_html_e( 'Your previous two-factor setup can no longer be read (the site security keys changed). Please set it up again.', 'bastion-security' ); ?></p>
				<?php endif; ?>
				<p><?php esc_html_e( 'Protect this account with an authenticator app such as Google Authenticator, Microsoft Authenticator, 1Password, Authy or Bitwarden.', 'bastion-security' ); ?></p>
				<p><button type="button" class="button button-primary" data-tfa="begin"><?php esc_html_e( 'Set up two-factor', 'bastion-security' ); ?></button></p>
			<?php endif; ?>
			<div class="bastion-tfa-panel" hidden></div>
		</div>
		<?php
	}

	public static function enforce() {
		if ( wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! self::is_required( $user ) || self::is_enabled( $user->ID ) ) {
			return;
		}
		$since = (int) get_user_meta( $user->ID, self::META_SINCE, true );
		if ( ! $since ) {
			$since = time();
			update_user_meta( $user->ID, self::META_SINCE, $since );
		}
		$grace = (int) Bastion_Settings::get( 'tfa_grace_days' ) * DAY_IN_SECONDS;
		global $pagenow;
		if ( time() > $since + $grace && 'profile.php' !== $pagenow ) {
			wp_safe_redirect( admin_url( 'profile.php?bastion_tfa_required=1#bastion-2fa' ) );
			exit;
		}
	}

	public static function notice() {
		$user = wp_get_current_user();
		if ( ! $user->ID || self::is_enabled( $user->ID ) || ! ( self::is_required( $user ) || self::is_broken( $user->ID ) ) ) {
			return;
		}
		$since = (int) get_user_meta( $user->ID, self::META_SINCE, true );
		$days  = max( 0, (int) ceil( ( $since + (int) Bastion_Settings::get( 'tfa_grace_days' ) * DAY_IN_SECONDS - time() ) / DAY_IN_SECONDS ) );
		$msg   = $days > 0
			? sprintf( _n( 'Your role requires two-factor authentication. Set it up within %d day to keep access.', 'Your role requires two-factor authentication. Set it up within %d days to keep access.', $days, 'bastion-security' ), $days )
			: __( 'Your role requires two-factor authentication. Set it up now to continue using the dashboard.', 'bastion-security' );
		printf( '<div class="notice notice-warning"><p><strong>Bastion:</strong> %s <a href="%s">%s</a></p></div>', esc_html( $msg ), esc_url( admin_url( 'profile.php#bastion-2fa' ) ), esc_html__( 'Set up now', 'bastion-security' ) );
	}

	/* ================================================================= AJAX */

	private static function ajax_guard() {
		check_ajax_referer( 'bastion_tfa', 'nonce' );
		if ( ! is_user_logged_in() ) {
			wp_send_json_error( array( 'message' => __( 'Not signed in.', 'bastion-security' ) ), 403 );
		}
		return wp_get_current_user();
	}

	public static function ajax_begin() {
		$user   = self::ajax_guard();
		$secret = Bastion_TOTP::generate_secret();
		update_user_meta( $user->ID, self::META_PENDING, Bastion_TOTP::encrypt( $secret ) );
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$issuer = '' !== trim( $issuer ) ? $issuer : wp_parse_url( home_url(), PHP_URL_HOST );
		wp_send_json_success(
			array(
				'secret' => trim( chunk_split( $secret, 4, ' ' ) ),
				'uri'    => Bastion_TOTP::uri( $secret, $user->user_login, $issuer ),
			)
		);
	}

	public static function ajax_confirm() {
		$user    = self::ajax_guard();
		$pending = Bastion_TOTP::decrypt( get_user_meta( $user->ID, self::META_PENDING, true ) );
		$code    = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		if ( ! $pending ) {
			wp_send_json_error( array( 'message' => __( 'Setup expired. Start again.', 'bastion-security' ) ) );
		}
		$counter = Bastion_TOTP::verify( $pending, $code, 0, 2 );
		if ( false === $counter ) {
			wp_send_json_error( array( 'message' => __( 'That code does not match. Make sure the time on your phone is set automatically.', 'bastion-security' ) ) );
		}
		update_user_meta( $user->ID, self::META_SECRET, Bastion_TOTP::encrypt( $pending ) );
		update_user_meta( $user->ID, self::META_LAST, $counter );
		delete_user_meta( $user->ID, self::META_PENDING );
		$codes = self::new_backup_codes( $user->ID );
		Bastion_Events::log( 'tfa_enabled', sprintf( 'Two-factor enabled for "%s"', $user->user_login ), array( 'severity' => Bastion_Events::LOW ) );
		wp_send_json_success( array( 'codes' => $codes ) );
	}

	public static function ajax_disable() {
		$actor  = self::ajax_guard();
		$target = isset( $_POST['user'] ) ? absint( $_POST['user'] ) : $actor->ID;
		if ( $target === $actor->ID ) {
			$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
			if ( ! self::verify_code( $actor, $code ) ) {
				wp_send_json_error( array( 'message' => __( 'Enter a valid current code (or a backup code) to turn two-factor off.', 'bastion-security' ) ) );
			}
		} elseif ( ! current_user_can( 'edit_user', $target ) || ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Not allowed.', 'bastion-security' ) ), 403 );
		}
		$target_user = get_userdata( $target );
		foreach ( array( self::META_SECRET, self::META_LAST, self::META_BACKUP, self::META_PENDING, self::META_LOGIN ) as $k ) {
			delete_user_meta( $target, $k );
		}
		Bastion_Events::log(
			'tfa_disabled',
			sprintf( 'Two-factor disabled for "%s"%s', $target_user ? $target_user->user_login : $target, $target === $actor->ID ? '' : ' by ' . $actor->user_login ),
			array( 'severity' => Bastion_Events::MEDIUM )
		);
		wp_send_json_success();
	}

	public static function ajax_regen() {
		$user = self::ajax_guard();
		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		if ( ! self::verify_code( $user, $code ) ) {
			wp_send_json_error( array( 'message' => __( 'Enter a valid current code first.', 'bastion-security' ) ) );
		}
		wp_send_json_success( array( 'codes' => self::new_backup_codes( $user->ID ) ) );
	}
}
