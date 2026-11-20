<?php
/**
 * Admin screens, form handlers and AJAX endpoints.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Admin {

	const CAP = 'manage_options';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_filter( 'submenu_file', array( __CLASS__, 'submenu_file' ) );
		add_action( 'admin_head', array( __CLASS__, 'menu_css' ) );
		add_filter( 'admin_body_class', array( __CLASS__, 'body_class' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( BASTION_FILE ), array( __CLASS__, 'action_links' ) );

		foreach ( array( 'save', 'block_ip', 'unblock_ip', 'prepend', 'export_log', 'allow_param', 'rules', 'allow_my_ip', 'import' , 'export' ) as $a ) {
			add_action( 'admin_post_bastion_' . $a, array( __CLASS__, 'post_' . $a ) );
		}
		foreach ( array( 'scan_start', 'scan_step', 'scan_stop', 'issue', 'quarantine', 'spam_scan', 'spam_empty', 'visitors_live' ) as $a ) {
			add_action( 'wp_ajax_bastion_' . $a, array( __CLASS__, 'ajax_' . $a ) );
		}
	}

	public static function pages() {
		return array(
			'bastion'          => __( 'Dashboard', 'bastion-security' ),
			'bastion-firewall' => __( 'Firewall', 'bastion-security' ),
			'bastion-login'    => __( 'Login security', 'bastion-security' ),
			'bastion-comments' => __( 'Comments', 'bastion-security' ),
			'bastion-visitors' => __( 'Visitors', 'bastion-security' ),
			'bastion-scanner'  => __( 'Scanner', 'bastion-security' ),
			'bastion-activity' => __( 'Activity log', 'bastion-security' ),
			'bastion-settings' => __( 'Settings', 'bastion-security' ),
		);
	}

	public static function menu() {
		$counts = Bastion_Scanner::issue_counts();
		$bad    = $counts[3] + $counts[4];
		$bubble = $bad ? ' <span class="awaiting-mod">' . (int) $bad . '</span>' : '';

		// One "Bastion Security" entry in the Prasat Digital menu; its other screens stay
		// registered (reachable from Bastion's own tabs) but aren't listed separately.
		foreach ( self::pages() as $slug => $title ) {
			add_submenu_page( Prasat_Hub::SLUG, $title . ' ‹ Bastion', 'bastion' === $slug ? 'Bastion Security' . $bubble : $title, self::CAP, $slug, array( __CLASS__, 'render' ) );
		}
	}

	/** Only "Bastion Security" is listed in the Prasat Digital menu; the other screens are reached from Bastion's tabs. */
	public static function menu_css() {
		$sel = array();
		foreach ( array_keys( self::pages() ) as $slug ) {
			if ( 'bastion' !== $slug ) {
				$sel[] = '#toplevel_page_prasat-digital .wp-submenu a[href="admin.php?page=' . $slug . '"]';
			}
		}
		echo '<style>' . implode( ',', $sel ) . '{display:none}</style>'; // phpcs:ignore -- built from fixed page slugs.
	}

	/** Keep "Bastion Security" highlighted on every Bastion screen. */
	public static function submenu_file( $file ) {
		$page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : ''; // phpcs:ignore
		return isset( self::pages()[ $page ] ) ? 'bastion' : $file;
	}

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=bastion' ) ) . '">' . esc_html__( 'Dashboard', 'bastion-security' ) . '</a>' );
		return $links;
	}

	public static function body_class( $c ) {
		$page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : ''; // phpcs:ignore
		return isset( self::pages()[ $page ] ) ? $c . ' pd-body' : $c;
	}

	public static function assets( $hook ) {
		$page    = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : ''; // phpcs:ignore
		$ours    = isset( self::pages()[ $page ] );
		$profile = in_array( $hook, array( 'profile.php', 'user-edit.php' ), true );
		if ( ! $ours && ! $profile ) {
			return;
		}
		$ver = BASTION_VERSION . '.' . (int) @filemtime( BASTION_DIR . 'assets/admin.css' ); // phpcs:ignore -- file time busts browser caches after updates.
		if ( $ours ) {
			wp_enqueue_style( 'bastion-ui', BASTION_URL . 'assets/prasat-ui.css', array(), $ver );
		}
		wp_enqueue_style( 'bastion-admin', BASTION_URL . 'assets/admin.css', $ours ? array( 'bastion-ui' ) : array(), $ver );
		wp_enqueue_script( 'bastion-qr', BASTION_URL . 'assets/qrcode.js', array(), BASTION_VERSION, true );
		wp_enqueue_script( 'bastion-ui', BASTION_URL . 'assets/prasat-ui.js', array(), $ver, true );
		wp_enqueue_script( 'bastion-admin', BASTION_URL . 'assets/admin.js', array( 'bastion-qr', 'bastion-ui' ), $ver, true );
		wp_localize_script(
			'bastion-admin',
			'BastionAdmin',
			array(
				'ajax'  => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( 'bastion_admin' ),
				'i18n'  => array(
					'confirmQuarantine' => __( 'Move this file to quarantine? If it belongs to a theme or plugin you trust, update that theme or plugin instead: the file may be needed. Should the site need it, Bastion puts it back automatically, and you can always restore it from the quarantine list.', 'bastion-security' ),
					'confirmRepair'     => __( 'Replace this file with the official WordPress.org copy? The current version is kept in quarantine.', 'bastion-security' ),
					'confirmDelete'     => __( 'Permanently delete this quarantined file? This cannot be undone.', 'bastion-security' ),
					'confirmDisable2fa' => __( 'Turn off two-factor authentication for this account?', 'bastion-security' ),
					'scanning'          => __( 'Scanning…', 'bastion-security' ),
					'error'             => __( 'Something went wrong. Please reload and try again.', 'bastion-security' ),
					'scanQR'            => __( '1. Scan this QR code with your authenticator app', 'bastion-security' ),
					'orKey'             => __( 'Or enter this key manually:', 'bastion-security' ),
					'enterCode'         => __( '2. Enter the 6-digit code it shows', 'bastion-security' ),
					'verify'            => __( 'Verify and turn on', 'bastion-security' ),
					'cancel'            => __( 'Cancel', 'bastion-security' ),
					'backupTitle'       => __( 'Save your backup codes', 'bastion-security' ),
					'backupHelp'        => __( 'Each code works once if you lose your phone. Store them somewhere safe — they will not be shown again.', 'bastion-security' ),
					'copy'              => __( 'Copy', 'bastion-security' ),
					'download'          => __( 'Download', 'bastion-security' ),
					'done'              => __( 'Done', 'bastion-security' ),
					'copied'            => __( 'Copied', 'bastion-security' ),
					'confirmSpamApply'  => __( 'Move every waiting comment that looks like spam to the spam folder? Real-looking comments stay waiting for you. You can still restore any of them from the spam folder.', 'bastion-security' ),
					'confirmSpamEmpty'  => __( 'Permanently delete every comment in the spam folder? This cannot be undone.', 'bastion-security' ),
					'checking'          => __( 'Checking %1$s of %2$s waiting comments…', 'bastion-security' ),
					'checked'           => __( '%1$s of %2$s waiting comments look like spam.', 'bastion-security' ),
					'moved'             => __( 'Moved %s comments to the spam folder.', 'bastion-security' ),
					'deleting'          => __( 'Deleted %s spam comments…', 'bastion-security' ),
					'deleted'           => __( 'Deleted %s spam comments. The spam folder is empty.', 'bastion-security' ),
					'visitor'           => __( '%s visitor', 'bastion-security' ),
					'visitors'          => __( '%s visitors', 'bastion-security' ),
					'nobody'            => __( 'Nobody right now.', 'bastion-security' ),
				),
			)
		);
	}

	/* ================================================================ notices */

	public static function notices() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$screen = get_current_screen();
		$ours   = $screen && false !== strpos( $screen->id, 'bastion' );
		if ( get_transient( 'bastion_welcome' ) && ! $ours ) {
			printf(
				'<div class="notice notice-success is-dismissible"><p><strong>%s</strong> %s <a class="button button-primary" style="margin-left:8px" href="%s">%s</a></p></div>',
				esc_html__( 'Bastion Security is protecting your site.', 'bastion-security' ),
				esc_html__( 'The firewall and login protection are already on. Run your first scan and set up two-factor.', 'bastion-security' ),
				esc_url( admin_url( 'admin.php?page=bastion' ) ),
				esc_html__( 'Open dashboard', 'bastion-security' )
			);
		}
		$note = $ours && isset( $_GET['bastion_msg'] ) ? get_transient( 'bastion_msg_' . get_current_user_id() ) : false; // phpcs:ignore
		if ( is_array( $note ) ) {
			delete_transient( 'bastion_msg_' . get_current_user_id() );
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', $note['error'] ? 'error' : 'success', esc_html( $note['msg'] ) );
		}
	}

	/* ================================================================ render */

	public static function render() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to access this page.', 'bastion-security' ) );
		}
		delete_transient( 'bastion_welcome' );
		Bastion_Firewall::ingest();
		$page  = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : 'bastion'; // phpcs:ignore
		$pages = self::pages();
		$view  = 'bastion' === $page ? 'dashboard' : substr( $page, 8 );
		echo '<div class="wrap bastion-wrap pd-app">';
		echo '<header class="pd-brand"><div class="pd-brand__id"><span class="pd-brand__mark pd-brand__mark--icon" aria-hidden="true"><img src="' . esc_url( BASTION_URL . 'assets/img/icon-bastion.png' ) . '" alt="" width="48" height="48"></span><div><p class="pd-brand__name">Bastion Security</p><p class="pd-brand__tag">' . esc_html__( 'Firewall · Login · Scan', 'bastion-security' ) . '</p></div></div><div class="pd-brand__side">';
		self::header_status();
		printf(
			'<a class="pd-credit" href="%1$s" target="_blank" rel="noopener noreferrer" title="prasatdigital.com"><img src="%2$s" alt="" width="20" height="20"><span>%3$s</span></a>',
			esc_url( 'https://www.prasatdigital.com' ),
			esc_url( BASTION_URL . 'assets/img/prasat-mark-white.svg' ),
			sprintf( /* translators: %s: Prasat Digital */ esc_html__( 'by %s', 'bastion-security' ), '<b>Prasat Digital</b>' )
		);
		echo '</div></header><nav class="pd-tabs" aria-label="Bastion">';
		foreach ( $pages as $slug => $title ) {
			printf( '<a href="%s" class="%s"%s>%s</a>', esc_url( admin_url( 'admin.php?page=' . $slug ) ), $slug === $page ? 'is-active' : '', $slug === $page ? ' aria-current="page"' : '', esc_html( $title ) );
		}
		echo '</nav>';
		echo '<h1 class="screen-reader-text">' . esc_html( $pages[ $page ] ) . '</h1><hr class="wp-header-end">';
		$file = BASTION_DIR . 'views/' . $view . '.php';
		if ( is_file( $file ) ) {
			include $file;
		}
		echo '</div>';
	}

	/** Compact protection status for the brand header. */
	private static function header_status() {
		$c       = Bastion_Scanner::issue_counts();
		$serious = (int) $c[3] + (int) $c[4];
		$open    = (int) $c[1] + (int) $c[2] + $serious;
		$fw      = Bastion_Firewall::status();
		if ( $serious ) {
			$dot  = 'bad';
			$text = sprintf( /* translators: %d: number */ _n( '%d serious issue', '%d serious issues', $serious, 'bastion-security' ), $serious );
		} elseif ( $open ) {
			$dot  = 'warn';
			$text = sprintf( /* translators: %d: number */ _n( '%d issue to review', '%d issues to review', $open, 'bastion-security' ), $open );
		} else {
			$dot  = '';
			$text = __( 'Protected', 'bastion-security' );
		}
		$fw_text = 'disabled' === $fw ? __( 'firewall off', 'bastion-security' ) : ( 'extended' === $fw ? __( 'firewall runs before WordPress', 'bastion-security' ) : __( 'firewall on', 'bastion-security' ) );
		if ( 'disabled' === $fw && ! $serious ) {
			$dot = 'warn';
		}
		printf( '<a class="pd-brand__status" href="%1$s"><span class="pd-dot%2$s" aria-hidden="true"></span>%3$s <small>%4$s</small></a>', esc_url( admin_url( 'admin.php?page=bastion' ) ), $dot ? ' pd-dot--' . esc_attr( $dot ) : '', esc_html( $text ), esc_html( $fw_text ) );
	}

	/** Render one settings field from the schema. */
	public static function field( $key ) {
		$schema = Bastion_Settings::schema();
		if ( ! isset( $schema[ $key ] ) ) {
			return;
		}
		$f     = $schema[ $key ];
		$value = Bastion_Settings::get( $key );
		$name  = 'bastion[' . $key . ']';
		$id    = 'bastion-' . $key;
		echo '<div class="bastion-field bastion-field--' . esc_attr( $f['type'] ) . '">';
		switch ( $f['type'] ) {
			case 'bool':
				printf(
					'<label class="bastion-switch"><input type="checkbox" id="%s" name="%s" value="1" %s><span class="bastion-switch__ui" aria-hidden="true"></span><span class="bastion-switch__label">%s</span></label>',
					esc_attr( $id ),
					esc_attr( $name ),
					checked( (bool) $value, true, false ),
					esc_html( $f['label'] )
				);
				break;
			case 'int':
				printf( '<label for="%s" class="bastion-label">%s</label>', esc_attr( $id ), esc_html( $f['label'] ) );
				printf(
					'<div class="bastion-inline"><input type="number" class="small-text" id="%s" name="%s" value="%d" min="%d" max="%d"> <span>%s</span></div>',
					esc_attr( $id ),
					esc_attr( $name ),
					(int) $value,
					isset( $f['min'] ) ? (int) $f['min'] : 0,
					isset( $f['max'] ) ? (int) $f['max'] : 999999,
					esc_html( isset( $f['suffix'] ) ? $f['suffix'] : '' )
				);
				break;
			case 'select':
				printf( '<label for="%s" class="bastion-label">%s</label><select id="%s" name="%s">', esc_attr( $id ), esc_html( $f['label'] ), esc_attr( $id ), esc_attr( $name ) );
				foreach ( $f['options'] as $k => $label ) {
					printf( '<option value="%s" %s>%s</option>', esc_attr( $k ), selected( $value, $k, false ), esc_html( $label ) );
				}
				echo '</select>';
				break;
			case 'list':
				printf( '<label for="%s" class="bastion-label">%s</label>', esc_attr( $id ), esc_html( $f['label'] ) );
				printf( '<textarea id="%s" name="%s" rows="4" class="large-text code">%s</textarea>', esc_attr( $id ), esc_attr( $name ), esc_textarea( implode( "\n", (array) $value ) ) );
				break;
			case 'email':
			case 'text':
				printf( '<label for="%s" class="bastion-label">%s</label>', esc_attr( $id ), esc_html( $f['label'] ) );
				printf( '<input type="%s" class="regular-text" id="%s" name="%s" value="%s" placeholder="%s">', 'email' === $f['type'] ? 'email' : 'text', esc_attr( $id ), esc_attr( $name ), esc_attr( $value ), esc_attr( 'email' === $f['type'] ? get_option( 'admin_email' ) : '' ) );
				break;
			case 'checks':
				printf( '<span class="bastion-label">%s</span><div class="bastion-checks">', esc_html( $f['label'] ) );
				foreach ( $f['options'] as $k => $label ) {
					printf(
						'<label><input type="checkbox" name="%s[]" value="%s" %s> %s</label>',
						esc_attr( $name ),
						esc_attr( $k ),
						checked( in_array( $k, (array) $value, true ), true, false ),
						esc_html( $label )
					);
				}
				echo '</div>';
				break;
			case 'roles':
				printf( '<span class="bastion-label">%s</span><div class="bastion-checks">', esc_html( $f['label'] ) );
				foreach ( wp_roles()->get_names() as $role => $label ) {
					printf(
						'<label><input type="checkbox" name="%s[]" value="%s" %s> %s</label>',
						esc_attr( $name ),
						esc_attr( $role ),
						checked( in_array( $role, (array) $value, true ), true, false ),
						esc_html( translate_user_role( $label ) )
					);
				}
				echo '</div>';
				break;
		}
		if ( ! empty( $f['desc'] ) ) {
			echo '<p class="description">' . esc_html( $f['desc'] ) . '</p>';
		}
		echo '</div>';
	}

	public static function form_open( $section ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="bastion-form">';
		echo '<input type="hidden" name="action" value="bastion_save"><input type="hidden" name="section" value="' . esc_attr( $section ) . '">';
		echo '<input type="hidden" name="return" value="' . esc_attr( isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : 'bastion' ) . '">'; // phpcs:ignore
		wp_nonce_field( 'bastion_save_' . $section );
	}

	public static function form_close() {
		echo '<p class="submit"><button type="submit" class="button button-primary">' . esc_html__( 'Save changes', 'bastion-security' ) . '</button></p></form>';
	}

	public static function severity_badge( $sev ) {
		$classes = array( 'info', 'low', 'medium', 'high', 'critical' );
		$sev     = max( 0, min( 4, (int) $sev ) );
		return '<span class="bastion-sev bastion-sev--' . $classes[ $sev ] . '">' . esc_html( Bastion_Scanner::severity_label( $sev ) ) . '</span>';
	}

	/* ======================================================= form handlers */

	private static function guard_post( $nonce_action ) {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'Not allowed.', 'bastion-security' ), 403 );
		}
		check_admin_referer( $nonce_action );
	}

	private static function back( $page, $msg = '', $error = false ) {
		$url = admin_url( 'admin.php?page=' . sanitize_key( $page ) );
		if ( $msg ) {
			// The message travels in a short-lived per-user transient, so a crafted link can't put text on the screen.
			set_transient( 'bastion_msg_' . get_current_user_id(), array( 'msg' => $msg, 'error' => (bool) $error ), 60 );
			$url = add_query_arg( 'bastion_msg', 1, $url );
		}
		wp_safe_redirect( $url );
		exit;
	}

	private static function return_page() {
		$page = isset( $_POST['return'] ) ? sanitize_key( $_POST['return'] ) : 'bastion'; // phpcs:ignore
		return isset( self::pages()[ $page ] ) ? $page : 'bastion';
	}

	public static function post_save() {
		$section = isset( $_POST['section'] ) ? sanitize_key( $_POST['section'] ) : ''; // phpcs:ignore
		self::guard_post( 'bastion_save_' . $section );
		$input  = isset( $_POST['bastion'] ) && is_array( $_POST['bastion'] ) ? $_POST['bastion'] : array(); // phpcs:ignore
		$values = Bastion_Settings::from_request( $section, $input );
		Bastion_Settings::update( $values );
		Bastion_Events::log( 'settings_changed', sprintf( '%s settings saved', ucfirst( $section ) ), array( 'severity' => Bastion_Events::LOW ) );
		if ( 'firewall' === $section && ! Bastion_Settings::get( 'waf_enabled' ) ) {
			Bastion_Firewall::remove_mu_loader();
		} elseif ( 'firewall' === $section ) {
			Bastion_Firewall::install_mu_loader();
		}
		self::back( self::return_page(), __( 'Settings saved.', 'bastion-security' ) );
	}

	public static function post_block_ip() {
		self::guard_post( 'bastion_block_ip' );
		$ip      = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$minutes = isset( $_POST['minutes'] ) ? absint( $_POST['minutes'] ) : 0;
		$reason  = isset( $_POST['reason'] ) && '' !== $_POST['reason'] ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : __( 'Blocked manually', 'bastion-security' );
		$ip      = Bastion_IP::normalize( $ip );
		if ( ! Bastion_IP::is_valid( $ip ) ) {
			self::back( self::return_page(), __( 'That is not a valid IP address.', 'bastion-security' ), true );
		}
		if ( $ip === Bastion_Waf::instance()->ip ) {
			self::back( self::return_page(), __( 'You cannot block your own IP address.', 'bastion-security' ), true );
		}
		if ( 0 === $minutes ) {
			$list   = (array) Bastion_Settings::get( 'ip_blocklist' );
			$list[] = $ip;
			Bastion_Settings::update( array( 'ip_blocklist' => $list ) );
		} else {
			Bastion_Firewall::block_ip( $ip, $minutes, $reason );
		}
		Bastion_Events::log( 'ip_blocked_manual', sprintf( 'Blocked %s %s', $ip, $minutes ? sprintf( 'for %d minutes', $minutes ) : 'permanently' ), array( 'severity' => Bastion_Events::LOW ) );
		self::back( self::return_page(), sprintf( __( '%s blocked.', 'bastion-security' ), $ip ) );
	}

	public static function post_unblock_ip() {
		self::guard_post( 'bastion_unblock_ip' );
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		Bastion_Firewall::unblock_ip( $ip );
		$list = array_values( array_diff( (array) Bastion_Settings::get( 'ip_blocklist' ), array( $ip ) ) );
		Bastion_Settings::update( array( 'ip_blocklist' => $list ) );
		Bastion_Events::log( 'ip_unblocked', sprintf( 'Unblocked %s', $ip ), array( 'severity' => Bastion_Events::LOW ) );
		self::back( self::return_page(), sprintf( __( '%s unblocked.', 'bastion-security' ), $ip ) );
	}

	public static function post_allow_my_ip() {
		self::guard_post( 'bastion_allow_my_ip' );
		$ip   = Bastion_Waf::instance()->ip;
		$list = (array) Bastion_Settings::get( 'ip_allowlist' );
		if ( ! in_array( $ip, $list, true ) ) {
			$list[] = $ip;
			Bastion_Settings::update( array( 'ip_allowlist' => $list ) );
		}
		Bastion_Firewall::unblock_ip( $ip );
		self::back( self::return_page(), sprintf( __( '%s added to the allowlist.', 'bastion-security' ), $ip ) );
	}

	public static function post_prepend() {
		self::guard_post( 'bastion_prepend' );
		$do = isset( $_POST['do'] ) ? sanitize_key( $_POST['do'] ) : '';
		if ( 'install' === $do ) {
			$res = Bastion_Firewall::install_prepend();
			if ( is_wp_error( $res ) ) {
				self::back( 'bastion-firewall', $res->get_error_message(), true );
			}
			$msg = 'user_ini' === Bastion_Firewall::server_method()
				? __( 'Extended protection installed. Your host may take up to 5 minutes to pick up the change.', 'bastion-security' )
				: __( 'Extended protection installed.', 'bastion-security' );
			self::back( 'bastion-firewall', $msg );
		}
		Bastion_Firewall::uninstall_prepend();
		self::back( 'bastion-firewall', __( 'Extended protection removed. The firewall keeps running in standard mode.', 'bastion-security' ) );
	}

	public static function post_allow_param() {
		self::guard_post( 'bastion_allow_param' );
		$event_id = isset( $_POST['event'] ) ? absint( $_POST['event'] ) : 0;
		global $wpdb;
		$row  = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . Bastion_DB::events_table() . ' WHERE id = %d', $event_id ) ); // phpcs:ignore
		$data = $row ? json_decode( (string) $row->data, true ) : array();
		if ( empty( $data['rule'] ) || empty( $data['uri'] ) ) {
			self::back( self::return_page(), __( 'This event cannot be allowlisted.', 'bastion-security' ), true );
		}
		$path  = (string) wp_parse_url( $data['uri'], PHP_URL_PATH );
		$param = isset( $data['param'] ) ? $data['param'] : '*';
		$list  = (array) Bastion_Settings::get( 'param_allowlist' );
		$list[] = array( $path ? $path : '*', $param, $data['rule'] );
		Bastion_Settings::update( array( 'param_allowlist' => array_values( array_unique( $list, SORT_REGULAR ) ) ) );
		Bastion_Firewall::unblock_ip( $row->ip );
		Bastion_Events::log( 'settings_changed', sprintf( 'Firewall exception added: rule %s, %s on %s', $data['rule'], $param, $path ), array( 'severity' => Bastion_Events::LOW ) );
		self::back( self::return_page(), __( 'Exception added. Requests like this will no longer be blocked.', 'bastion-security' ) );
	}

	public static function post_rules() {
		self::guard_post( 'bastion_rules' );
		$rules    = array_keys( require BASTION_DIR . 'waf/rules.php' );
		$enabled  = isset( $_POST['rules'] ) ? array_map( 'sanitize_key', (array) $_POST['rules'] ) : array();
		$disabled = array_values( array_diff( $rules, $enabled ) );
		$allow    = array();
		if ( isset( $_POST['exceptions'] ) ) {
			foreach ( preg_split( '/\r?\n/', wp_unslash( $_POST['exceptions'] ) ) as $line ) { // phpcs:ignore
				$parts = array_map( 'trim', explode( '|', sanitize_text_field( $line ) ) );
				if ( 3 === count( $parts ) && '' !== $parts[0] ) {
					$allow[] = $parts;
				}
			}
		}
		Bastion_Settings::update(
			array(
				'disabled_rules'  => $disabled,
				'param_allowlist' => $allow,
			)
		);
		self::back( 'bastion-firewall', __( 'Firewall rules saved.', 'bastion-security' ) );
	}

	public static function post_export_log() {
		self::guard_post( 'bastion_export_log' );
		$args = array(
			'group'    => isset( $_POST['group'] ) ? sanitize_key( $_POST['group'] ) : '',
			'search'   => isset( $_POST['s'] ) ? sanitize_text_field( wp_unslash( $_POST['s'] ) ) : '',
			'per_page' => 500,
		);
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=bastion-activity-' . gmdate( 'Y-m-d' ) . '.csv' );
		$out = fopen( 'php://output', 'w' );
		fputcsv( $out, array( 'time_utc', 'type', 'severity', 'ip', 'user', 'message', 'details' ) );
		for ( $page = 1; $page <= 40; $page++ ) {
			$args['page'] = $page;
			$res          = Bastion_Events::query( $args );
			foreach ( $res['rows'] as $r ) {
				$row = array( gmdate( 'Y-m-d H:i:s', $r->created ), $r->type, $r->severity, $r->ip, $r->username, $r->message, (string) $r->data );
				// Neutralise spreadsheet formula injection from attacker-controlled text.
				$row = array_map(
					function ( $v ) {
						return preg_match( '/^[=+\-@\t\r]/', (string) $v ) ? "'" . $v : $v;
					},
					$row
				);
				fputcsv( $out, $row );
			}
			if ( $page >= $res['pages'] ) {
				break;
			}
		}
		fclose( $out );
		exit;
	}

	public static function post_export() {
		self::guard_post( 'bastion_export' );
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=bastion-settings-' . gmdate( 'Y-m-d' ) . '.json' );
		echo wp_json_encode( array( 'bastion' => BASTION_VERSION, 'settings' => Bastion_Settings::all() ), JSON_PRETTY_PRINT );
		exit;
	}

	public static function post_import() {
		self::guard_post( 'bastion_import' );
		if ( empty( $_FILES['file']['tmp_name'] ) || ! is_uploaded_file( $_FILES['file']['tmp_name'] ) ) { // phpcs:ignore
			self::back( 'bastion-settings', __( 'Choose a settings file to import.', 'bastion-security' ), true );
		}
		$data = json_decode( (string) file_get_contents( $_FILES['file']['tmp_name'] ), true ); // phpcs:ignore
		if ( empty( $data['settings'] ) || ! is_array( $data['settings'] ) ) {
			self::back( 'bastion-settings', __( 'That is not a Bastion settings file.', 'bastion-security' ), true );
		}
		Bastion_Settings::update( $data['settings'] );
		Bastion_Events::log( 'settings_changed', 'Settings imported from file', array( 'severity' => Bastion_Events::LOW ) );
		self::back( 'bastion-settings', __( 'Settings imported.', 'bastion-security' ) );
	}

	/* ================================================================= AJAX */

	private static function guard_ajax() {
		check_ajax_referer( 'bastion_admin', 'nonce' );
		if ( ! current_user_can( self::CAP ) ) {
			wp_send_json_error( array( 'message' => __( 'Not allowed.', 'bastion-security' ) ), 403 );
		}
	}

	public static function scan_payload( $state ) {
		$state  = wp_parse_args( $state, array( 'status' => 'idle', 'step' => '', 'files_total' => 0, 'files_done' => 0 ) );
		$i      = (int) array_search( $state['step'], Bastion_Scanner::STEPS, true );
		$total  = max( 1, (int) $state['files_total'] );
		if ( 'complete' === $state['status'] ) {
			$pct = 100;
		} elseif ( 'files' === $state['step'] ) {
			$pct = (int) ( 15 + 70 * min( 1, $state['files_done'] / $total ) ); // File checks are the bulk of the work.
		} elseif ( $i < 3 ) {
			$pct = $i * 5;
		} else {
			$pct = min( 99, 85 + ( $i - 4 ) * 3 );
		}
		return array(
			'status'  => isset( $state['status'] ) ? $state['status'] : 'idle',
			'step'    => isset( $state['step'] ) ? $state['step'] : '',
			'message' => isset( $state['message'] ) ? $state['message'] : '',
			'percent' => $pct,
			'files'   => isset( $state['files_done'] ) ? (int) $state['files_done'] : 0,
			'found'   => isset( $state['found'] ) ? (int) $state['found'] : 0,
		);
	}

	public static function ajax_scan_start() {
		self::guard_ajax();
		Bastion_Scanner::start( 'manual' );
		wp_send_json_success( self::scan_payload( Bastion_Scanner::run_for( 5 ) ) );
	}

	public static function ajax_scan_step() {
		self::guard_ajax();
		$state = Bastion_Scanner::is_running() ? Bastion_Scanner::run_for( 12 ) : Bastion_Scanner::state();
		wp_send_json_success( self::scan_payload( $state ) );
	}

	public static function ajax_scan_stop() {
		self::guard_ajax();
		Bastion_Scanner::stop();
		wp_send_json_success( self::scan_payload( Bastion_Scanner::state() ) );
	}

	public static function ajax_issue() {
		self::guard_ajax();
		$id = isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0;
		$do = isset( $_POST['do'] ) ? sanitize_key( $_POST['do'] ) : '';
		switch ( $do ) {
			case 'ignore':
				Bastion_Scanner::set_status( $id, 'ignored' );
				wp_send_json_success( array( 'message' => __( 'Ignored. It will reappear if the file changes.', 'bastion-security' ) ) );
				break;
			case 'unignore':
				Bastion_Scanner::set_status( $id, 'open' );
				wp_send_json_success( array( 'message' => __( 'Issue reopened.', 'bastion-security' ) ) );
				break;
			case 'view':
				$res = Bastion_Scanner::view_file( $id );
				break;
			case 'quarantine':
				$res = Bastion_Scanner::quarantine( $id );
				break;
			case 'repair':
				$res = Bastion_Scanner::repair( $id );
				break;
			default:
				$res = new WP_Error( 'bastion_bad_action', 'Unknown action' );
		}
		if ( is_wp_error( $res ) ) {
			wp_send_json_error( array( 'message' => $res->get_error_message() ) );
		}
		wp_send_json_success( is_array( $res ) ? $res : array( 'message' => __( 'Done.', 'bastion-security' ) ) );
	}

	public static function ajax_quarantine() {
		self::guard_ajax();
		$name = isset( $_POST['name'] ) ? sanitize_file_name( wp_unslash( $_POST['name'] ) ) : '';
		$do   = isset( $_POST['do'] ) ? sanitize_key( $_POST['do'] ) : '';
		$res  = 'restore' === $do ? Bastion_Scanner::restore_quarantined( $name ) : Bastion_Scanner::delete_quarantined( $name );
		if ( is_wp_error( $res ) ) {
			wp_send_json_error( array( 'message' => $res->get_error_message() ) );
		}
		wp_send_json_success( array( 'message' => 'restore' === $do ? __( 'File restored.', 'bastion-security' ) : __( 'File deleted.', 'bastion-security' ) ) );
	}

	/* ======================================================== comment clean-up */

	public static function ajax_spam_scan() {
		self::guard_ajax();
		$cursor = isset( $_POST['cursor'] ) ? absint( $_POST['cursor'] ) : 0; // phpcs:ignore -- nonce checked in guard_ajax().
		$apply  = ! empty( $_POST['apply'] ); // phpcs:ignore
		@set_time_limit( 60 ); // phpcs:ignore
		$res = Bastion_Comments::cleanup_batch( $cursor, $apply, 500 );
		if ( $apply && $res['done'] ) {
			Bastion_Events::log( 'spam_cleanup', 'Waiting comments that looked like spam were moved to the spam folder', array( 'severity' => Bastion_Events::LOW ) );
		}
		$res['pending'] = Bastion_Comments::counts()['pending'];
		wp_send_json_success( $res );
	}

	public static function ajax_spam_empty() {
		self::guard_ajax();
		@set_time_limit( 60 ); // phpcs:ignore
		$res = Bastion_Comments::empty_spam_batch( 1000 );
		if ( $res['done'] ) {
			Bastion_Events::log( 'spam_cleanup', 'The comment spam folder was emptied', array( 'severity' => Bastion_Events::LOW ) );
		}
		wp_send_json_success( $res );
	}

	/* ================================================================ visitors */

	public static function ajax_visitors_live() {
		self::guard_ajax();
		$live = Bastion_Visitors::live();
		$today = Bastion_Visitors::totals( Bastion_Visitors::day_start() );
		wp_send_json_success(
			array(
				'live'  => $live['count'],
				'pages' => array_map(
					function ( $r ) {
						return array( 'path' => $r->path, 'n' => (int) $r->n );
					},
					(array) $live['pages']
				),
				'today' => $today,
			)
		);
	}

	/**
	 * Numbers for the Prasat Digital dashboard (Prasat_Hub::render): tiles, recent activity,
	 * 7-day charts and running jobs.
	 */
	public static function dashboard() {
		$now     = time();
		$today   = class_exists( 'Bastion_Visitors' ) ? Bastion_Visitors::day_start() : strtotime( 'today' );
		$attacks = Bastion_Events::count_since( Bastion_Events::ATTACK_TYPES, $today );
		$blocks  = count( Bastion_Firewall::active_blocks() );
		$counts  = Bastion_Scanner::issue_counts();
		$serious = (int) $counts[3] + (int) $counts[4];
		$fw      = Bastion_Firewall::status();
		$out     = array( 'tiles' => array(), 'activity' => array(), 'charts' => array(), 'jobs' => array() );

		$out['tiles'][] = array(
			'area'  => __( 'Security', 'bastion-security' ),
			'value' => number_format_i18n( $attacks ),
			'label' => __( 'attacks blocked today', 'bastion-security' ),
			'sub'   => ( 'disabled' === $fw ? __( 'Firewall off', 'bastion-security' ) : __( 'Firewall on', 'bastion-security' ) ) . ' · ' . sprintf( _n( '%d IP blocked now', '%d IPs blocked now', $blocks, 'bastion-security' ), $blocks ),
			'tone'  => $serious || 'disabled' === $fw ? 'bad' : ( (int) $counts[2] ? 'warn' : 'ok' ),
			'url'   => admin_url( 'admin.php?page=bastion' ),
		);

		if ( Bastion_Settings::get( 'visitors_enabled' ) ) {
			$t    = Bastion_Visitors::totals( $today );
			$live = Bastion_Visitors::live();
			$out['tiles'][] = array(
				'area'  => __( 'Visitors', 'bastion-security' ),
				'value' => number_format_i18n( $t['visitors'] ),
				'label' => __( 'visitors today', 'bastion-security' ),
				'sub'   => sprintf( _n( '%s on the site now', '%s on the site now', $live['count'], 'bastion-security' ), number_format_i18n( $live['count'] ) ) . ' · ' . sprintf( __( '%s views', 'bastion-security' ), number_format_i18n( $t['views'] ) ),
				'tone'  => 'ok',
				'url'   => admin_url( 'admin.php?page=bastion-visitors' ),
			);
			$series = Bastion_Visitors::series( 7 );
			$sum    = 0;
			$views  = 0;
			foreach ( $series as $d ) {
				$sum   += $d['visitors'];
				$views += $d['views'];
			}
			$out['charts'][] = array(
				'title'   => __( 'Visitors · last 7 days', 'bastion-security' ),
				'summary' => sprintf( __( '%1$s visitors · %2$s views', 'bastion-security' ), number_format_i18n( $sum ), number_format_i18n( $views ) ),
				'values'  => wp_list_pluck( $series, 'visitors' ),
				'tone'    => 'brand',
				'url'     => admin_url( 'admin.php?page=bastion-visitors' ),
			);
		} else {
			$out['tiles'][] = array(
				'area'  => __( 'Visitors', 'bastion-security' ),
				'value' => __( 'Off', 'bastion-security' ),
				'label' => __( 'visitor counting', 'bastion-security' ),
				'sub'   => __( 'Private, no cookies. Turn it on in one click.', 'bastion-security' ),
				'tone'  => 'muted',
				'url'   => admin_url( 'admin.php?page=bastion-visitors' ),
			);
		}

		$days  = Bastion_Events::daily_series( 7 );
		$spam  = Bastion_Events::count_since( array( 'comment_blocked', 'comment_spam' ), $now - WEEK_IN_SECONDS );
		$total = 0;
		foreach ( $days as $d ) {
			$total += $d['attacks'];
		}
		$out['charts'][] = array(
			'title'   => __( 'Attacks blocked · last 7 days', 'bastion-security' ),
			'summary' => sprintf( __( '%1$s blocked · %2$s spam comments stopped', 'bastion-security' ), number_format_i18n( $total ), number_format_i18n( $spam ) ),
			'values'  => wp_list_pluck( $days, 'attacks' ),
			'tone'    => 'bad',
			'url'     => admin_url( 'admin.php?page=bastion-activity&group=attacks' ),
		);

		$recent = Bastion_Events::query( array( 'min_severity' => 1, 'per_page' => 6 ) );
		foreach ( $recent['rows'] as $e ) {
			$out['activity'][] = array(
				'time' => (int) $e->created,
				'text' => $e->message,
				'tone' => (int) $e->severity >= 3 ? 'bad' : ( (int) $e->severity >= 2 ? 'warn' : 'brand' ),
				'url'  => admin_url( 'admin.php?page=bastion-activity' ),
			);
		}

		if ( Bastion_Scanner::is_running() ) {
			$p = self::scan_payload( Bastion_Scanner::state() );
			$out['jobs'][] = array(
				'title'   => __( 'Malware scan running', 'bastion-security' ),
				'percent' => (int) $p['percent'],
				'text'    => $p['message'],
				'url'     => admin_url( 'admin.php?page=bastion-scanner' ),
			);
		}
		return $out;
	}
}
