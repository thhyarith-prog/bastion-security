<?php
/**
 * Settings screen (hardening, alerts, maintenance).
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

$post_url = admin_url( 'admin-post.php' );
?>
<div class="bastion-grid bastion-grid--2">
	<section class="bastion-card">
		<h2><?php esc_html_e( 'Hardening', 'bastion-security' ); ?></h2>
		<?php Bastion_Admin::form_open( 'hardening' ); ?>
		<div class="bastion-fields">
			<?php
			foreach ( array( 'disable_file_editor', 'hide_wp_version', 'security_headers', 'hsts', 'uploads_php_block' ) as $k ) {
				Bastion_Admin::field( $k );
			}
			?>
		</div>
		<?php Bastion_Admin::form_close(); ?>
		<details class="bastion-more">
			<summary><?php esc_html_e( 'Using Nginx?', 'bastion-security' ); ?></summary>
			<p class="description"><?php esc_html_e( 'Nginx ignores .htaccess. Add this to your server block to block PHP in uploads and protect Bastion\'s data folder:', 'bastion-security' ); ?></p>
			<pre class="bastion-snippet"><?php echo esc_html( Bastion_Hardening::nginx_snippet() ); ?></pre>
		</details>
	</section>

	<section class="bastion-card">
		<h2><?php esc_html_e( 'Alerts and data', 'bastion-security' ); ?></h2>
		<?php Bastion_Admin::form_open( 'general' ); ?>
		<div class="bastion-fields">
			<?php
			foreach ( array( 'alert_email', 'alert_new_admin', 'alert_admin_new_ip', 'alert_scan', 'alert_plugins', 'alert_lockouts', 'log_retention_days', 'delete_on_uninstall' ) as $k ) {
				Bastion_Admin::field( $k );
			}
			?>
		</div>
		<?php Bastion_Admin::form_close(); ?>
	</section>
</div>

<div class="bastion-grid bastion-grid--2">
	<section class="bastion-card">
		<h2><?php esc_html_e( 'Import / export', 'bastion-security' ); ?></h2>
		<p class="bastion-muted"><?php esc_html_e( 'Copy your Bastion configuration to another site.', 'bastion-security' ); ?></p>
		<form method="post" action="<?php echo esc_url( $post_url ); ?>" style="margin-bottom:16px">
			<?php wp_nonce_field( 'bastion_export' ); ?>
			<input type="hidden" name="action" value="bastion_export">
			<button class="button"><?php esc_html_e( 'Export settings', 'bastion-security' ); ?></button>
		</form>
		<form method="post" action="<?php echo esc_url( $post_url ); ?>" enctype="multipart/form-data" class="bastion-inline-form" data-pd-confirm="<?php esc_attr_e( 'Replace all Bastion settings with the ones in this file?', 'bastion-security' ); ?>">
			<?php wp_nonce_field( 'bastion_import' ); ?>
			<input type="hidden" name="action" value="bastion_import">
			<input type="file" name="file" accept="application/json,.json" required aria-label="<?php esc_attr_e( 'Settings file to import', 'bastion-security' ); ?>">
			<button class="button"><?php esc_html_e( 'Import', 'bastion-security' ); ?></button>
		</form>
	</section>

	<section class="bastion-card">
		<h2><?php esc_html_e( 'Diagnostics', 'bastion-security' ); ?></h2>
		<dl class="bastion-dl">
			<dt><?php esc_html_e( 'Bastion version', 'bastion-security' ); ?></dt><dd><?php echo esc_html( BASTION_VERSION ); ?></dd>
			<dt><?php esc_html_e( 'Firewall mode', 'bastion-security' ); ?></dt><dd><?php echo esc_html( Bastion_Firewall::status() ); ?></dd>
			<dt><?php esc_html_e( 'Data folder', 'bastion-security' ); ?></dt><dd class="code"><?php echo esc_html( BASTION_WAF_DIR ); ?> <?php echo is_writable( BASTION_WAF_DIR ) ? '✓' : '✗ ' . esc_html__( 'not writable', 'bastion-security' ); ?></dd>
			<dt><?php esc_html_e( 'Rate-limit storage', 'bastion-security' ); ?></dt><dd><?php echo function_exists( 'apcu_enabled' ) && apcu_enabled() ? 'APCu' : esc_html__( 'Files', 'bastion-security' ); ?></dd>
			<dt>PHP</dt><dd><?php echo esc_html( PHP_VERSION . ' (' . PHP_SAPI . ')' ); ?></dd>
			<dt>auto_prepend_file</dt><dd class="code"><?php echo esc_html( ini_get( 'auto_prepend_file' ) ? ini_get( 'auto_prepend_file' ) : '—' ); ?></dd>
			<dt><?php esc_html_e( 'Encryption', 'bastion-security' ); ?></dt><dd><?php echo function_exists( 'openssl_encrypt' ) ? esc_html__( 'Two-factor secrets encrypted (AES-256-GCM)', 'bastion-security' ) : esc_html__( 'OpenSSL missing: secrets stored unencrypted', 'bastion-security' ); ?></dd>
		</dl>
	</section>
</div>
