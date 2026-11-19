<?php
/**
 * Activity log, change auditing and email alerts.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Events {

	const INFO     = 0;
	const LOW      = 1;
	const MEDIUM   = 2;
	const HIGH     = 3;
	const CRITICAL = 4;

	/** Event types that count as "attacks blocked" on the dashboard. */
	const ATTACK_TYPES = array( 'waf', 'probe', 'bad_bot', 'rate_limit', 'auto_block', 'user_enum', 'country', 'blocklist', 'ip_block', 'lockout', 'xmlrpc', 'rate_404' );

	public static function init() {
		add_action( 'user_register', array( __CLASS__, 'on_user_register' ), 20 );
		add_action( 'delete_user', array( __CLASS__, 'on_delete_user' ) );
		add_action( 'set_user_role', array( __CLASS__, 'on_set_user_role' ), 10, 3 );
		add_action( 'add_user_role', array( __CLASS__, 'on_add_user_role' ), 10, 2 );
		add_action( 'grant_super_admin', array( __CLASS__, 'on_grant_super_admin' ) );
		add_action( 'profile_update', array( __CLASS__, 'on_profile_update' ), 10, 2 );
		add_action( 'activated_plugin', array( __CLASS__, 'on_plugin' ), 10, 1 );
		add_action( 'deactivated_plugin', array( __CLASS__, 'on_plugin_deactivated' ), 10, 1 );
		add_action( 'deleted_plugin', array( __CLASS__, 'on_plugin_deleted' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrade' ), 10, 2 );
		add_action( 'switch_theme', array( __CLASS__, 'on_switch_theme' ), 10, 1 );
		add_action( '_core_updated_successfully', array( __CLASS__, 'on_core_updated' ) );
		foreach ( array( 'users_can_register', 'default_role', 'admin_email', 'siteurl', 'home' ) as $opt ) {
			add_action( 'update_option_' . $opt, array( __CLASS__, 'on_option_change' ), 10, 3 );
		}
	}

	/* ================================================================ logging */

	public static function log( $type, $message, array $args = array() ) {
		global $wpdb;
		$user = wp_get_current_user();
		$row  = array(
			'created'  => isset( $args['time'] ) ? (int) $args['time'] : time(),
			'type'     => substr( $type, 0, 40 ),
			'severity' => isset( $args['severity'] ) ? (int) $args['severity'] : self::INFO,
			'ip'       => isset( $args['ip'] ) ? substr( (string) $args['ip'], 0, 45 ) : self::ip(),
			'user_id'  => isset( $args['user_id'] ) ? (int) $args['user_id'] : (int) $user->ID,
			'username' => substr( isset( $args['username'] ) ? (string) $args['username'] : (string) $user->user_login, 0, 100 ),
			'message'  => (string) $message,
			'data'     => ! empty( $args['data'] ) ? wp_json_encode( $args['data'] ) : null,
		);
		$wpdb->insert( Bastion_DB::events_table(), $row ); // phpcs:ignore
		return (int) $wpdb->insert_id;
	}

	public static function ip() {
		return class_exists( 'Bastion_Waf' ) ? Bastion_Waf::instance()->ip : ( isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '' );
	}

	/**
	 * Send an alert email, at most once per $throttle seconds per key.
	 */
	public static function alert( $key, $subject, $body, $throttle = 0 ) {
		if ( $throttle > 0 ) {
			$t = 'bastion_alert_' . md5( $key );
			if ( get_transient( $t ) ) {
				return false;
			}
			set_transient( $t, 1, $throttle );
		}
		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$subject = sprintf( '[%s] %s', $site, $subject );
		$body   .= "\n\n—\n" . sprintf(
			/* translators: %s: URL */
			__( 'Sent by Bastion Security on %s', 'bastion-security' ),
			home_url( '/' )
		) . "\n" . admin_url( 'admin.php?page=bastion' );
		return wp_mail( Bastion_Settings::alert_email(), $subject, $body );
	}

	public static function purge() {
		global $wpdb;
		$days = max( 1, (int) Bastion_Settings::get( 'log_retention_days' ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . Bastion_DB::events_table() . ' WHERE created < %d LIMIT 50000', time() - $days * DAY_IN_SECONDS ) ); // phpcs:ignore
	}

	/* ================================================================ queries */

	public static function query( array $args ) {
		global $wpdb;
		$table = Bastion_DB::events_table();
		$where = array( '1=1' );
		$vals  = array();
		if ( ! empty( $args['group'] ) ) {
			$groups = self::groups();
			if ( isset( $groups[ $args['group'] ] ) ) {
				$types   = $groups[ $args['group'] ]['types'];
				$where[] = 'type IN (' . implode( ',', array_fill( 0, count( $types ), '%s' ) ) . ')';
				$vals    = array_merge( $vals, $types );
			}
		}
		if ( ! empty( $args['ip'] ) ) {
			$where[] = 'ip = %s';
			$vals[]  = $args['ip'];
		}
		if ( ! empty( $args['search'] ) ) {
			$like    = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where[] = '(message LIKE %s OR username LIKE %s OR ip LIKE %s OR data LIKE %s)';
			array_push( $vals, $like, $like, $like, $like );
		}
		if ( isset( $args['min_severity'] ) && $args['min_severity'] > 0 ) {
			$where[] = 'severity >= %d';
			$vals[]  = (int) $args['min_severity'];
		}
		$per_page = isset( $args['per_page'] ) ? max( 1, min( 500, (int) $args['per_page'] ) ) : 50;
		$page     = isset( $args['page'] ) ? max( 1, (int) $args['page'] ) : 1;
		$sql_w    = implode( ' AND ', $where );

		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$sql_w}";
		$rows_sql  = "SELECT * FROM {$table} WHERE {$sql_w} ORDER BY id DESC LIMIT %d OFFSET %d";
		$total     = (int) $wpdb->get_var( $vals ? $wpdb->prepare( $count_sql, $vals ) : $count_sql ); // phpcs:ignore
		$rows      = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $vals, array( $per_page, ( $page - 1 ) * $per_page ) ) ) ); // phpcs:ignore
		return array(
			'rows'  => $rows,
			'total' => $total,
			'pages' => (int) ceil( $total / $per_page ),
		);
	}

	public static function groups() {
		return array(
			'attacks' => array( 'label' => __( 'Firewall', 'bastion-security' ), 'types' => array_merge( self::ATTACK_TYPES, array( 'learning' ) ) ),
			'logins'  => array( 'label' => __( 'Logins', 'bastion-security' ), 'types' => array( 'login_success', 'login_failed', 'lockout_added', 'tfa_failed', 'tfa_success', 'password_reset_limit' ) ),
			'changes' => array( 'label' => __( 'Site changes', 'bastion-security' ), 'types' => array( 'user_created', 'user_deleted', 'role_changed', 'profile_changed', 'plugin_activated', 'plugin_deactivated', 'plugin_deleted', 'plugin_installed', 'plugin_updated', 'theme_installed', 'theme_updated', 'theme_switched', 'core_updated', 'option_changed', 'super_admin' ) ),
			'comments' => array( 'label' => __( 'Comments', 'bastion-security' ), 'types' => array( 'comment_blocked', 'comment_spam', 'comment_held', 'comment_would_block', 'spam_cleanup' ) ),
			'security' => array( 'label' => __( 'Bastion', 'bastion-security' ), 'types' => array( 'scan_complete', 'file_quarantined', 'file_restored', 'file_repaired', 'tfa_enabled', 'tfa_disabled', 'settings_changed', 'ip_unblocked', 'ip_blocked_manual', 'auto_fix' ) ),
		);
	}

	/** Counts per day for the last N days (attacks vs. failed logins). */
	public static function daily_series( $days = 14 ) {
		global $wpdb;
		$table  = Bastion_DB::events_table();
		$since  = strtotime( 'today', current_time( 'timestamp', true ) ) - ( $days - 1 ) * DAY_IN_SECONDS;
		$attack = self::ATTACK_TYPES;
		$in     = implode( ',', array_fill( 0, count( $attack ), '%s' ) );
		$sql    = "SELECT FLOOR((created - %d) / 86400) AS d,
			SUM(CASE WHEN type IN ($in) THEN 1 ELSE 0 END) AS attacks,
			SUM(CASE WHEN type = 'login_failed' THEN 1 ELSE 0 END) AS logins
			FROM {$table} WHERE created >= %d GROUP BY d";
		$rows   = $wpdb->get_results( $wpdb->prepare( $sql, array_merge( array( $since ), $attack, array( $since ) ) ) ); // phpcs:ignore
		$out    = array();
		for ( $i = 0; $i < $days; $i++ ) {
			$out[ $i ] = array( 'day' => $since + $i * DAY_IN_SECONDS, 'attacks' => 0, 'logins' => 0 );
		}
		foreach ( (array) $rows as $r ) {
			$d = (int) $r->d;
			if ( isset( $out[ $d ] ) ) {
				$out[ $d ]['attacks'] = (int) $r->attacks;
				$out[ $d ]['logins']  = (int) $r->logins;
			}
		}
		return array_values( $out );
	}

	public static function count_since( array $types, $since ) {
		global $wpdb;
		$in = implode( ',', array_fill( 0, count( $types ), '%s' ) );
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . Bastion_DB::events_table() . " WHERE created >= %d AND type IN ($in)", array_merge( array( $since ), $types ) ) ); // phpcs:ignore
	}

	public static function top_ips( $since, $limit = 8, $types = null ) {
		global $wpdb;
		if ( null === $types ) {
			$types   = self::ATTACK_TYPES;
			$types[] = 'login_failed';
		}
		$in      = implode( ',', array_fill( 0, count( $types ), '%s' ) );
		return $wpdb->get_results( $wpdb->prepare( 'SELECT ip, COUNT(*) AS hits, MAX(created) AS last_seen FROM ' . Bastion_DB::events_table() . " WHERE created >= %d AND ip <> '' AND type IN ($in) GROUP BY ip ORDER BY hits DESC LIMIT %d", array_merge( array( $since ), $types, array( $limit ) ) ) ); // phpcs:ignore
	}

	/* ========================================================= audit hooks */

	public static function on_user_register( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$admin = user_can( $user, 'manage_options' ) || user_can( $user, 'promote_users' );
		self::log(
			'user_created',
			sprintf( 'User "%s" created with role %s', $user->user_login, implode( ', ', $user->roles ) ),
			array( 'severity' => $admin ? self::HIGH : self::INFO, 'data' => array( 'new_user' => $user_id ) )
		);
		if ( $admin ) {
			self::alert_new_admin( $user, __( 'created', 'bastion-security' ) );
		}
	}

	public static function on_delete_user( $user_id ) {
		$user = get_userdata( $user_id );
		self::log( 'user_deleted', sprintf( 'User "%s" deleted', $user ? $user->user_login : '#' . $user_id ), array( 'severity' => self::LOW ) );
	}

	public static function on_set_user_role( $user_id, $role, $old_roles ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		// A brand-new account getting its first role is covered by user_created.
		if ( empty( $old_roles ) && time() - (int) strtotime( $user->user_registered . ' UTC' ) < 120 ) {
			return;
		}
		$escalated = 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true );
		self::log(
			'role_changed',
			sprintf( 'Role of "%s" changed from %s to %s', $user->user_login, implode( ', ', (array) $old_roles ) ?: '—', $role ),
			array( 'severity' => $escalated ? self::HIGH : self::LOW )
		);
		if ( $escalated ) {
			self::alert_new_admin( $user, __( 'promoted to administrator', 'bastion-security' ) );
		}
	}

	public static function on_add_user_role( $user_id, $role ) {
		if ( 'administrator' !== $role || doing_action( 'set_user_role' ) || doing_action( 'user_register' ) ) {
			return;
		}
		$user = get_userdata( $user_id );
		if ( $user ) {
			self::log( 'role_changed', sprintf( 'Administrator role added to "%s"', $user->user_login ), array( 'severity' => self::HIGH ) );
			self::alert_new_admin( $user, __( 'granted the administrator role', 'bastion-security' ) );
		}
	}

	public static function on_grant_super_admin( $user_id ) {
		$user = get_userdata( $user_id );
		if ( $user ) {
			self::log( 'super_admin', sprintf( 'Super admin granted to "%s"', $user->user_login ), array( 'severity' => self::HIGH ) );
			self::alert_new_admin( $user, __( 'granted super admin', 'bastion-security' ) );
		}
	}

	private static function alert_new_admin( $user, $what ) {
		if ( ! Bastion_Settings::get( 'alert_new_admin' ) ) {
			return;
		}
		$actor = wp_get_current_user();
		self::alert(
			'new_admin_' . $user->ID,
			sprintf( __( 'Administrator account %s', 'bastion-security' ), $what ),
			sprintf(
				"User: %s (%s)\nAction: %s\nBy: %s\nIP: %s\nTime: %s\n\n%s",
				$user->user_login,
				$user->user_email,
				$what,
				$actor->ID ? $actor->user_login : __( 'unknown / not logged in', 'bastion-security' ),
				self::ip(),
				wp_date( 'Y-m-d H:i:s T' ),
				__( 'If you did not expect this, your site may be compromised. Remove the account and change all administrator passwords.', 'bastion-security' )
			),
			60
		);
	}

	public static function on_profile_update( $user_id, $old ) {
		$new = get_userdata( $user_id );
		if ( ! $new || ! $old ) {
			return;
		}
		$changes = array();
		if ( $old->user_email !== $new->user_email ) {
			$changes[] = sprintf( 'email %s → %s', $old->user_email, $new->user_email );
		}
		if ( $old->user_pass !== $new->user_pass ) {
			$changes[] = 'password';
		}
		if ( $changes ) {
			self::log( 'profile_changed', sprintf( 'Profile of "%s" changed: %s', $new->user_login, implode( '; ', $changes ) ), array( 'severity' => self::LOW ) );
		}
	}

	public static function on_plugin( $plugin ) {
		self::log( 'plugin_activated', 'Plugin activated: ' . $plugin, array( 'severity' => self::LOW ) );
		self::maybe_alert_plugins( 'Plugin activated: ' . $plugin );
	}

	public static function on_plugin_deactivated( $plugin ) {
		self::log( 'plugin_deactivated', 'Plugin deactivated: ' . $plugin, array( 'severity' => self::LOW ) );
		self::maybe_alert_plugins( 'Plugin deactivated: ' . $plugin );
	}

	public static function on_plugin_deleted( $plugin, $deleted ) {
		if ( $deleted ) {
			self::log( 'plugin_deleted', 'Plugin deleted: ' . $plugin, array( 'severity' => self::LOW ) );
			self::maybe_alert_plugins( 'Plugin deleted: ' . $plugin );
		}
	}

	public static function on_upgrade( $upgrader, $extra ) {
		if ( empty( $extra['type'] ) || empty( $extra['action'] ) ) {
			return;
		}
		$type   = $extra['type'];
		$action = 'install' === $extra['action'] ? 'installed' : 'updated';
		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) ) {
			return;
		}
		$items = array();
		if ( 'installed' === $action && is_object( $upgrader ) && ! empty( $upgrader->new_plugin_data['Name'] ) ) {
			$items[] = $upgrader->new_plugin_data['Name'];
		} elseif ( 'installed' === $action && is_object( $upgrader ) && ! empty( $upgrader->new_theme_data['Name'] ) ) {
			$items[] = $upgrader->new_theme_data['Name'];
		} else {
			$items = isset( $extra[ $type . 's' ] ) ? (array) $extra[ $type . 's' ] : ( isset( $extra[ $type ] ) ? array( $extra[ $type ] ) : array() );
		}
		$msg = ucfirst( $type ) . ' ' . $action . ': ' . ( $items ? implode( ', ', $items ) : '?' );
		self::log( $type . '_' . $action, $msg, array( 'severity' => 'installed' === $action ? self::LOW : self::INFO ) );
		if ( 'installed' === $action ) {
			self::maybe_alert_plugins( $msg );
		}
	}

	public static function on_switch_theme( $name ) {
		self::log( 'theme_switched', 'Theme switched to ' . $name, array( 'severity' => self::LOW ) );
		self::maybe_alert_plugins( 'Theme switched to ' . $name );
	}

	public static function on_core_updated( $version ) {
		self::log( 'core_updated', 'WordPress updated to ' . $version );
	}

	private static function maybe_alert_plugins( $msg ) {
		if ( Bastion_Settings::get( 'alert_plugins' ) ) {
			$user = wp_get_current_user();
			self::alert( 'plugins_' . md5( $msg ), $msg, $msg . "\nBy: " . ( $user->ID ? $user->user_login : 'system' ) . "\nIP: " . self::ip(), 60 );
		}
	}

	public static function on_option_change( $old, $new, $option ) {
		$severity = in_array( $option, array( 'siteurl', 'home', 'admin_email' ), true ) ? self::MEDIUM : self::LOW;
		self::log(
			'option_changed',
			sprintf( 'Setting "%s" changed from "%s" to "%s"', $option, is_scalar( $old ) ? $old : wp_json_encode( $old ), is_scalar( $new ) ? $new : wp_json_encode( $new ) ),
			array( 'severity' => $severity )
		);

		// Classic takeover: open registration + administrator as default role. Revert it.
		if ( in_array( $option, array( 'users_can_register', 'default_role' ), true ) ) {
			$role = get_role( get_option( 'default_role' ) );
			if ( get_option( 'users_can_register' ) && $role && ( $role->has_cap( 'manage_options' ) || $role->has_cap( 'edit_users' ) || $role->has_cap( 'promote_users' ) ) ) {
				remove_action( 'update_option_default_role', array( __CLASS__, 'on_option_change' ), 10 );
				update_option( 'default_role', 'subscriber' );
				add_action( 'update_option_default_role', array( __CLASS__, 'on_option_change' ), 10, 3 );
				self::log( 'auto_fix', 'Blocked privilege escalation: new-user default role was set to a privileged role while registration is open. Reverted to subscriber.', array( 'severity' => self::CRITICAL ) );
				self::alert(
					'default_role_escalation',
					__( 'Blocked an attempt to make new registrations administrators', 'bastion-security' ),
					sprintf( "The default role for new users was changed to \"%s\" while anyone can register. This is a common takeover technique; Bastion reverted it to Subscriber.\nIP: %s", $role->name, self::ip() ),
					300
				);
			}
		}
	}
}
