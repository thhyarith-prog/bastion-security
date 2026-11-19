<?php
/**
 * Plugin bootstrap, cron and lifecycle.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Plugin {

	/** @var Bastion_Plugin */
	private static $instance;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		Bastion_Events::init();
		Bastion_Firewall::init();
		Bastion_Login::init();
		Bastion_Two_Factor::init();
		Bastion_Hardening::init();
		Bastion_Scanner::init();
		Bastion_Comments::init();
		Bastion_Visitors::init();
		if ( class_exists( 'Bastion_Admin' ) ) {
			Bastion_Admin::init();
		}

		add_filter( 'cron_schedules', array( $this, 'cron_schedules' ) );
		add_action( 'bastion_cron_frequent', array( $this, 'cron_frequent' ) );
		add_action( 'bastion_cron_daily', array( $this, 'cron_daily' ) );
		add_action( 'bastion_remove_prepend_file', array( 'Bastion_Firewall', 'remove_prepend_file' ) );
		add_action( 'init', array( $this, 'maybe_upgrade' ), 1 );
		add_action( 'upgrader_process_complete', array( $this, 'after_self_update' ), 20, 2 );
		add_action( 'bastion_settings_updated', array( $this, 'reschedule_scans' ) );
	}

	public function cron_schedules( $schedules ) {
		$schedules['bastion_5min'] = array(
			'interval' => 5 * MINUTE_IN_SECONDS,
			'display'  => 'Every 5 minutes (Bastion)',
		);
		return $schedules;
	}

	public function cron_frequent() {
		Bastion_Firewall::ingest();
	}

	public function cron_daily() {
		Bastion_Events::purge();
		Bastion_Visitors::purge();
		Bastion_Firewall::storage()->cleanup_rate_files();
		// Re-assert loader and config in case a deploy or restore wiped them.
		Bastion_Firewall::write_config();
		if ( Bastion_Settings::get( 'waf_enabled' ) ) {
			Bastion_Firewall::install_mu_loader();
		}
	}

	public static function schedule_events() {
		if ( ! wp_next_scheduled( 'bastion_cron_frequent' ) ) {
			wp_schedule_event( time() + 60, 'bastion_5min', 'bastion_cron_frequent' );
		}
		if ( ! wp_next_scheduled( 'bastion_cron_daily' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'bastion_cron_daily' );
		}
		self::schedule_scan();
	}

	private static function schedule_scan() {
		$schedule = Bastion_Settings::get( 'scan_schedule' );
		$next     = wp_next_scheduled( 'bastion_scheduled_scan' );
		$current  = $next ? wp_get_schedule( 'bastion_scheduled_scan' ) : false;
		if ( 'off' === $schedule ) {
			wp_clear_scheduled_hook( 'bastion_scheduled_scan' );
			return;
		}
		if ( $current === $schedule ) {
			return;
		}
		wp_clear_scheduled_hook( 'bastion_scheduled_scan' );
		// Run at a quiet hour (03:00 site time), randomised a little to spread load on shared hosts.
		$start = strtotime( 'tomorrow 03:00', current_time( 'timestamp' ) ) - ( (int) get_option( 'gmt_offset' ) * HOUR_IN_SECONDS ) + wp_rand( 0, 1800 );
		wp_schedule_event( $start, $schedule, 'bastion_scheduled_scan' );
	}

	public function reschedule_scans() {
		self::schedule_scan();
	}

	public static function activate() {
		Bastion_DB::install();
		if ( false === get_option( Bastion_Settings::OPTION ) ) {
			add_option( Bastion_Settings::OPTION, Bastion_Settings::defaults(), '', true );
		}
		Bastion_Firewall::storage()->ensure_dir();
		Bastion_Firewall::write_config();
		Bastion_Firewall::install_mu_loader();
		Bastion_Hardening::sync_uploads_rule();
		add_filter( 'cron_schedules', array( self::instance(), 'cron_schedules' ) );
		self::schedule_events();
		update_option( 'bastion_version', BASTION_VERSION, false );
		if ( ! get_option( 'bastion_comment_shield_since' ) ) {
			// The comment shield is new: cached pages don't have its form fields yet, so hold
			// (rather than reject) comments without them for the first hours.
			update_option( 'bastion_comment_shield_since', time(), false );
			if ( class_exists( 'Slipstream_Cache' ) && method_exists( 'Slipstream_Cache', 'purge_all_soon' ) ) {
				Slipstream_Cache::purge_all_soon();
			}
		}
		if ( ! get_option( 'bastion_installed' ) ) {
			update_option( 'bastion_installed', time(), false );
			set_transient( 'bastion_welcome', 1, HOUR_IN_SECONDS );
		}
	}

	public static function deactivate() {
		Bastion_Firewall::remove_mu_loader();
		if ( get_option( 'bastion_prepend_installed' ) ) {
			Bastion_Firewall::uninstall_prepend();
		}
		Bastion_Firewall::disable_config();
		Bastion_Scanner::stop();
		foreach ( array( 'bastion_cron_frequent', 'bastion_cron_daily', 'bastion_scheduled_scan', Bastion_Scanner::CRON ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
		// The uploads PHP block stays: it is harmless and still protective.
	}

	public function maybe_upgrade() {
		if ( get_option( 'bastion_version' ) !== BASTION_VERSION || (int) get_option( 'bastion_db_version' ) < Bastion_DB::DB_VERSION ) {
			self::activate();
		}
		self::schedule_events();
	}

	public function after_self_update( $upgrader, $extra ) {
		if ( isset( $extra['type'], $extra['plugins'] ) && 'plugin' === $extra['type'] && in_array( plugin_basename( BASTION_FILE ), (array) $extra['plugins'], true ) ) {
			Bastion_Firewall::write_config();
			Bastion_Firewall::install_mu_loader();
		}
	}
}
