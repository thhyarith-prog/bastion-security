<?php
/**
 * Bastion firewall bootstrap.
 *
 * Loaded, in order of preference, by:
 *  1. auto_prepend_file (bastion-waf-prepend.php in the site root) — runs before WordPress,
 *     and also protects PHP files that are requested directly;
 *  2. the mu-plugin loader — runs before any regular plugin;
 *  3. the plugin itself — fallback if the loaders are missing.
 *
 * Fails open: an error here must never take the site down.
 *
 * @package Bastion_Security
 */

if ( defined( 'BASTION_WAF_LOADED' ) ) {
	return;
}
define( 'BASTION_WAF_LOADED', true );

if ( ! defined( 'BASTION_WAF_DIR' ) ) {
	// wp-content/plugins/bastion-security/waf -> wp-content/bastion-waf.
	define( 'BASTION_WAF_DIR', dirname( __DIR__, 3 ) . '/bastion-waf' );
}

require_once __DIR__ . '/class-bastion-ip.php';
require_once __DIR__ . '/class-bastion-waf-storage.php';
require_once __DIR__ . '/class-bastion-waf.php';

if ( 'cli' === PHP_SAPI || defined( 'BASTION_WAF_DISABLE' ) ) {
	return;
}

try {
	Bastion_Waf::instance()->run_early();
} catch ( Throwable $e ) {
	error_log( 'Bastion Security firewall error: ' . $e->getMessage() );
}
