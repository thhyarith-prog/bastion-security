<?php
/**
 * Plugin Name:       Bastion Security
 * Description:       Lightweight, privacy-first security for WordPress: pre-WordPress firewall, brute-force protection, two-factor login, file integrity and malware scanning, known-vulnerability alerts, hardening and an activity log. Every feature is free and nothing is sent to a vendor cloud.
 * Version:           1.1.6
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Update URI:        https://github.com/thhyarith-prog/bastion-security
 * Author:            Prasat Digital
 * Author URI:        https://www.prasatdigital.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       bastion-security
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

define( 'BASTION_VERSION', '1.1.6' );
define( 'BASTION_FILE', __FILE__ );
define( 'BASTION_DIR', plugin_dir_path( __FILE__ ) );
define( 'BASTION_URL', plugin_dir_url( __FILE__ ) );
if ( ! defined( 'BASTION_WAF_DIR' ) ) {
	define( 'BASTION_WAF_DIR', WP_CONTENT_DIR . '/bastion-waf' );
}

// Updates come from the GitHub releases of this plugin.
require_once BASTION_DIR . 'includes/prasat-updater.php';
Prasat_Updater::register( __FILE__, 'thhyarith-prog/bastion-security' );

// Firewall: normally already running from the mu-plugin or auto_prepend_file; this is the fallback.
require_once BASTION_DIR . 'waf/bootstrap.php';

require_once BASTION_DIR . 'includes/class-bastion-settings.php';
require_once BASTION_DIR . 'includes/class-bastion-db.php';
require_once BASTION_DIR . 'includes/class-bastion-events.php';
require_once BASTION_DIR . 'includes/class-bastion-firewall.php';
require_once BASTION_DIR . 'includes/class-bastion-login.php';
require_once BASTION_DIR . 'includes/class-bastion-totp.php';
require_once BASTION_DIR . 'includes/class-bastion-two-factor.php';
require_once BASTION_DIR . 'includes/class-bastion-hardening.php';
require_once BASTION_DIR . 'includes/class-bastion-signatures.php';
require_once BASTION_DIR . 'includes/class-bastion-scanner.php';
require_once BASTION_DIR . 'includes/class-bastion-comments.php';
require_once BASTION_DIR . 'includes/class-bastion-visitors.php';
require_once BASTION_DIR . 'includes/class-bastion-plugin.php';
require_once BASTION_DIR . 'includes/class-bastion-autofix.php';

if ( is_admin() || wp_doing_ajax() ) {
	require_once BASTION_DIR . 'includes/class-bastion-admin.php';
	require_once BASTION_DIR . 'includes/prasat-hub.php';
	Prasat_Hub::register( 'bastion', array( 'assets' => BASTION_URL . 'assets/', 'health' => array( 'Bastion_Hardening', 'health' ), 'dashboard' => array( 'Bastion_Admin', 'dashboard' ), 'fixes' => array( 'Bastion_Autofix', 'fixes' ) ) );
}

// If a quarantined file turns out to be needed (the site crashes requiring it), restore it at once.
// wp_php_error_message runs inside WordPress's fatal-error handler, just before the error page.
add_filter(
	'wp_php_error_message',
	function ( $message, $error ) {
		if ( Bastion_Scanner::rescue_from_error( $error ) ) {
			$message .= '<p>' . esc_html__( 'Bastion Security has put back a file it had quarantined, because the site needs it. Reload this page.', 'bastion-security' ) . '</p>';
		}
		return $message;
	},
	1,
	2
);
register_shutdown_function( // fallback when the WordPress fatal-error handler is turned off
	function () {
		Bastion_Scanner::rescue_from_error( error_get_last() );
	}
);

register_activation_hook( __FILE__, array( 'Bastion_Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Bastion_Plugin', 'deactivate' ) );

Bastion_Plugin::instance();
