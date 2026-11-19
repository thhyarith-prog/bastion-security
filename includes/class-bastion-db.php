<?php
/**
 * Database tables.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_DB {

	const DB_VERSION = 2;

	public static function events_table() {
		global $wpdb;
		return $wpdb->prefix . 'bastion_events';
	}

	public static function issues_table() {
		global $wpdb;
		return $wpdb->prefix . 'bastion_issues';
	}

	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$events  = self::events_table();
		$issues  = self::issues_table();

		dbDelta(
			"CREATE TABLE {$events} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created int(10) unsigned NOT NULL,
			type varchar(40) NOT NULL,
			severity tinyint(3) unsigned NOT NULL DEFAULT 0,
			ip varchar(45) NOT NULL DEFAULT '',
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			username varchar(100) NOT NULL DEFAULT '',
			message text NOT NULL,
			data longtext NULL,
			PRIMARY KEY  (id),
			KEY created (created),
			KEY type_created (type,created),
			KEY ip (ip)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$issues} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			issue_key char(32) NOT NULL,
			type varchar(40) NOT NULL,
			severity tinyint(3) unsigned NOT NULL DEFAULT 1,
			status varchar(20) NOT NULL DEFAULT 'open',
			file varchar(1024) NOT NULL DEFAULT '',
			title varchar(255) NOT NULL DEFAULT '',
			details longtext NULL,
			file_hash varchar(64) NOT NULL DEFAULT '',
			first_seen int(10) unsigned NOT NULL DEFAULT 0,
			last_seen int(10) unsigned NOT NULL DEFAULT 0,
			scan_id int(10) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (id),
			UNIQUE KEY issue_key (issue_key),
			KEY status_severity (status,severity)
			) {$charset};"
		);

		// Visitor counts: no IP column by design (see Bastion_Visitors). Kept 30 days.
		$hits = $wpdb->prefix . 'bastion_hits';
		dbDelta(
			"CREATE TABLE {$hits} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ts int(10) unsigned NOT NULL,
			day int(10) unsigned NOT NULL,
			vid char(16) NOT NULL DEFAULT '',
			path varchar(191) NOT NULL DEFAULT '',
			ref varchar(100) NOT NULL DEFAULT '',
			cc char(2) NOT NULL DEFAULT '',
			device tinyint(3) unsigned NOT NULL DEFAULT 0,
			browser tinyint(3) unsigned NOT NULL DEFAULT 0,
			kind tinyint(3) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (id),
			KEY ts (ts),
			KEY day_kind (day,kind)
			) {$charset};"
		);

		update_option( 'bastion_db_version', self::DB_VERSION, false );
	}

	public static function drop() {
		global $wpdb;
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::events_table() ); // phpcs:ignore
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::issues_table() ); // phpcs:ignore
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'bastion_hits' ); // phpcs:ignore
	}
}
