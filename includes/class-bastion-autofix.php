<?php
/**
 * Fixes that Smart AI Optimize (Prasat Digital dashboard) may make on its own, after Lifeboat
 * has taken a backup. Each one is small, checked and can be undone from the dashboard.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Autofix {

	/** Seconds the comment clean-up may use in one request; the rest waits for the next click. */
	const COMMENT_BUDGET = 25;

	/** For Prasat_Hub: check id => [ apply, undo ]. */
	public static function fixes() {
		return array(
			'comment_backlog' => array(
				'apply' => array( __CLASS__, 'clean_comments' ),
				'undo'  => array( __CLASS__, 'undo_comments' ),
			),
			'comment_shield'  => array(
				'apply' => array( __CLASS__, 'shield_on' ),
				'undo'  => array( __CLASS__, 'undo_setting' ),
			),
			'waf_mode'        => array(
				'apply' => array( __CLASS__, 'firewall_protect' ),
				'undo'  => array( __CLASS__, 'undo_setting' ),
			),
			'waf_extended'    => array(
				'apply' => array( __CLASS__, 'firewall_extended' ),
				'undo'  => array( __CLASS__, 'undo_extended' ),
			),
		);
	}

	/* ============================================================ comments */

	/** Moves the waiting comments that look like spam to the Spam folder (nothing is deleted). */
	public static function clean_comments() {
		$end    = time() + self::COMMENT_BUDGET;
		$cursor = 0;
		$ids    = array();
		$done   = false;
		while ( time() < $end ) {
			$r      = Bastion_Comments::cleanup_batch( $cursor, true, 500 );
			$cursor = $r['cursor'];
			$ids    = array_merge( $ids, $r['ids'] );
			if ( $r['done'] ) {
				$done = true;
				break;
			}
		}
		if ( ! $ids ) {
			return array( 'skip' => true ); // Nothing spammy: the waiting comments need a human.
		}
		$token = strtolower( wp_generate_password( 12, false ) );
		update_option( 'bastion_autofix_spam_' . $token, $ids, false );
		$left = Bastion_Comments::counts()['pending'];
		Bastion_Events::log( 'auto_fix', sprintf( 'Smart AI Optimize moved %d spam comments to the Spam folder.', count( $ids ) ), array( 'severity' => Bastion_Events::INFO ) );
		$did = sprintf(
			/* translators: %s: number of comments */
			_n( 'Moved %s spam comment to the Spam folder', 'Moved %s spam comments to the Spam folder', count( $ids ), 'bastion-security' ),
			number_format_i18n( count( $ids ) )
		);
		if ( ! $done ) {
			$did .= __( ' (more left: click again to continue)', 'bastion-security' );
		} elseif ( $left ) {
			/* translators: %s: number of comments */
			$did .= sprintf( __( '. %s look genuine and wait for you in Comments.', 'bastion-security' ), number_format_i18n( $left ) );
		}
		return array( 'ok' => true, 'did' => $did, 'undo' => $token );
	}

	public static function undo_comments( $token ) {
		global $wpdb;
		$token = sanitize_key( (string) $token );
		$ids   = array_map( 'intval', (array) get_option( 'bastion_autofix_spam_' . $token, array() ) );
		if ( ! $ids ) {
			return new WP_Error( 'bastion_undo_gone', __( 'The list of moved comments is no longer available.', 'bastion-security' ) );
		}
		foreach ( array_chunk( $ids, 1000 ) as $chunk ) {
			$in = implode( ',', $chunk );
			$wpdb->query( "UPDATE {$wpdb->comments} SET comment_approved = '0' WHERE comment_approved = 'spam' AND comment_ID IN ($in)" ); // phpcs:ignore -- integers only.
			clean_comment_cache( $chunk );
		}
		wp_cache_delete( 'comments-0', 'counts' );
		delete_option( 'bastion_autofix_spam_' . $token );
		return true;
	}

	/* ============================================================ settings */

	private static function set( $key, $value ) {
		$before = Bastion_Settings::get( $key );
		Bastion_Settings::update( array( $key => $value ) );
		return array( 'key' => $key, 'value' => $before );
	}

	public static function undo_setting( $data ) {
		if ( ! is_array( $data ) || empty( $data['key'] ) || ! in_array( $data['key'], array( 'waf_mode', 'comment_shield' ), true ) ) {
			return new WP_Error( 'bastion_undo_bad', __( 'This change cannot be undone automatically.', 'bastion-security' ) );
		}
		Bastion_Settings::update( array( $data['key'] => $data['value'] ) );
		return true;
	}

	public static function shield_on() {
		if ( 'on' === Bastion_Comments::mode() ) {
			return array( 'skip' => true );
		}
		return array( 'ok' => true, 'did' => __( 'Turned on the comment spam shield', 'bastion-security' ), 'undo' => self::set( 'comment_shield', 'on' ) );
	}

	public static function firewall_protect() {
		if ( 'learning' !== Bastion_Settings::get( 'waf_mode' ) ) {
			return array( 'skip' => true );
		}
		return array( 'ok' => true, 'did' => __( 'Switched the firewall from learning to blocking attacks', 'bastion-security' ), 'undo' => self::set( 'waf_mode', 'block' ) );
	}

	/* ===================================================== extended firewall */

	/**
	 * Runs the firewall before WordPress. On Apache/LiteSpeed the change applies at once, so the
	 * home page is loaded right after; if it fails, the change is taken back straight away.
	 */
	public static function firewall_extended() {
		$status = Bastion_Firewall::status();
		if ( 'disabled' === $status || 'extended' === $status || 'pending' === $status ) {
			return array( 'skip' => true );
		}
		$retry  = 'stuck' === $status;
		$method = $retry ? Bastion_Firewall::untried_method() : Bastion_Firewall::server_method();
		if ( '' === $method ) {
			return array( 'skip' => true ); // Both ways tried: this server doesn't allow it.
		}
		$res = Bastion_Firewall::install_prepend( $method );
		if ( is_wp_error( $res ) ) {
			return new WP_Error( 'bastion_extended', $res->get_error_message() );
		}
		if ( 'htaccess' === $method ) {
			$probe = wp_remote_get(
				add_query_arg( 'bastion-probe', time(), home_url( '/' ) ),
				array( 'timeout' => 20, 'redirection' => 3, 'sslverify' => apply_filters( 'https_local_ssl_verify', false ) )
			);
			$code  = is_wp_error( $probe ) ? 0 : (int) wp_remote_retrieve_response_code( $probe );
			if ( ! $code || $code >= 500 ) {
				Bastion_Firewall::uninstall_prepend();
				return new WP_Error( 'bastion_extended_probe', __( 'Running the firewall before WordPress was tried, but the site could not be checked afterwards, so the change was taken back.', 'bastion-security' ) );
			}
		}
		Bastion_Events::log( 'auto_fix', 'Smart AI Optimize set the firewall to run before WordPress.', array( 'severity' => Bastion_Events::INFO ) );
		if ( $retry ) {
			$did = __( 'Your server ignored the first way of running the firewall before WordPress, so Bastion tried another way (it applies within 10 minutes)', 'bastion-security' );
		} else {
			$did = 'htaccess' === $method
				? __( 'Set the firewall to run before WordPress, and checked that the site still loads', 'bastion-security' )
				: __( 'Set the firewall to run before WordPress (your server applies it within 5 minutes)', 'bastion-security' );
		}
		return array( 'ok' => true, 'did' => $did, 'undo' => $method );
	}

	public static function undo_extended() {
		Bastion_Firewall::uninstall_prepend();
		return true;
	}
}
