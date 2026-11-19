<?php
/**
 * Uninstall: remove loaders always; remove data only when the user opted in.
 *
 * @package Bastion_Security
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

$bastion_waf_dir = WP_CONTENT_DIR . '/bastion-waf';
$bastion_mu      = ( defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins' ) . '/bastion-waf-loader.php';
if ( is_file( $bastion_mu ) ) {
	@unlink( $bastion_mu ); // phpcs:ignore
}
if ( is_file( ABSPATH . 'bastion-waf-prepend.php' ) && ! ini_get( 'auto_prepend_file' ) ) {
	@unlink( ABSPATH . 'bastion-waf-prepend.php' ); // phpcs:ignore
}

$bastion_settings = get_option( 'bastion_settings', array() );
if ( empty( $bastion_settings['delete_on_uninstall'] ) ) {
	return;
}

global $wpdb;
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bastion_events" ); // phpcs:ignore
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bastion_issues" ); // phpcs:ignore
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bastion_hits" ); // phpcs:ignore

foreach ( array( 'bastion_settings', 'bastion_version', 'bastion_db_version', 'bastion_installed', 'bastion_scan_state', 'bastion_core_sums', 'bastion_last_scan_completed', 'bastion_prepend_installed', 'bastion_secret', 'bastion_visit_salt', 'bastion_comment_shield_since', 'bastion_comment_form_hash', 'bastion_visitors_state' ) as $bastion_opt ) {
	delete_option( $bastion_opt );
}
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE '\\_bastion\\_%'" ); // phpcs:ignore
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_bastion\\_%' OR option_name LIKE '\\_transient\\_timeout\\_bastion\\_%'" ); // phpcs:ignore

// Remove the data folder (config, blocks, quarantine).
if ( is_dir( $bastion_waf_dir ) ) {
	$bastion_it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $bastion_waf_dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
	foreach ( $bastion_it as $bastion_f ) {
		$bastion_f->isDir() ? @rmdir( $bastion_f->getPathname() ) : @unlink( $bastion_f->getPathname() ); // phpcs:ignore
	}
	@rmdir( $bastion_waf_dir ); // phpcs:ignore
}
