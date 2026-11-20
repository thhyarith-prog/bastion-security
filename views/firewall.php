<?php
/**
 * Firewall screen.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

$status   = Bastion_Firewall::status();
$blocks   = Bastion_Firewall::active_blocks();
$rules    = require BASTION_DIR . 'waf/rules.php';
$disabled = (array) Bastion_Settings::get( 'disabled_rules' );
$events   = Bastion_Events::query( array( 'group' => 'attacks', 'per_page' => 25 ) );
$my_ip    = Bastion_Waf::instance()->ip;
$post_url = admin_url( 'admin-post.php' );
$method   = Bastion_Firewall::server_method();
?>
<div class="bastion-grid bastion-grid--2">
	<section class="bastion-card">
		<h2><?php esc_html_e( 'Protection level', 'bastion-security' ); ?></h2>
		<ol class="bastion-levels">
			<li class="<?php echo in_array( $status, array( 'basic', 'standard', 'pending', 'stuck', 'extended' ), true ) ? 'is-done' : ''; ?>"><strong><?php esc_html_e( 'Basic', 'bastion-security' ); ?></strong> — <?php esc_html_e( 'runs inside the plugin', 'bastion-security' ); ?></li>
			<li class="<?php echo in_array( $status, array( 'standard', 'pending', 'stuck', 'extended' ), true ) ? 'is-done' : ''; ?>"><strong><?php esc_html_e( 'Standard', 'bastion-security' ); ?></strong> — <?php esc_html_e( 'runs before every other plugin', 'bastion-security' ); ?></li>
			<li class="<?php echo 'extended' === $status ? 'is-done' : ( 'pending' === $status ? 'is-pending' : '' ); ?>"><strong><?php esc_html_e( 'Extended', 'bastion-security' ); ?></strong> — <?php esc_html_e( 'runs before WordPress itself, and also guards PHP files that attackers request directly', 'bastion-security' ); ?></li>
		</ol>
		<?php if ( 'disabled' === $status ) : ?>
			<p><?php esc_html_e( 'The firewall is turned off below.', 'bastion-security' ); ?></p>
		<?php elseif ( get_option( 'bastion_prepend_installed' ) || 'extended' === $status ) : ?>
			<?php $used = (string) get_option( 'bastion_prepend_installed' ); ?>
			<?php if ( 'pending' === $status ) : ?>
				<p class="bastion-note">
					<?php
					echo esc_html(
						'user_ini' === $used
							? __( 'Set up in .user.ini. PHP reads that file again within 5 minutes, then extended mode starts by itself.', 'bastion-security' )
							: __( 'Set up in .htaccess. Extended mode starts with the next page load if this server allows it.', 'bastion-security' )
					);
					?>
				</p>
			<?php elseif ( 'stuck' === $status && Bastion_Firewall::untried_method() ) : ?>
				<p class="bastion-note">
					<?php
					/* translators: %s: .htaccess or .user.ini */
					echo esc_html( sprintf( __( 'Set up in %s, but this server has not applied it. The firewall still runs in standard mode. Bastion can try the other way your server may support.', 'bastion-security' ), 'user_ini' === $used ? '.user.ini' : '.htaccess' ) );
					?>
				</p>
				<form method="post" action="<?php echo esc_url( $post_url ); ?>">
					<?php wp_nonce_field( 'bastion_prepend' ); ?>
					<input type="hidden" name="action" value="bastion_prepend"><input type="hidden" name="do" value="retry">
					<button class="button button-primary"><?php esc_html_e( 'Try another way', 'bastion-security' ); ?></button>
				</form>
			<?php elseif ( 'stuck' === $status ) : ?>
				<p class="bastion-note"><?php esc_html_e( 'This server does not let the firewall run before WordPress (both .htaccess and .user.ini were tried). Nothing is wrong: standard protection runs before every other plugin and theme. You can ask your host to allow auto_prepend_file, or remove the setting below.', 'bastion-security' ); ?></p>
			<?php endif; ?>
			<form method="post" action="<?php echo esc_url( $post_url ); ?>" data-pd-confirm="<?php esc_attr_e( 'Remove extended protection? The firewall will then start only after other plugins load.', 'bastion-security' ); ?>">
				<?php wp_nonce_field( 'bastion_prepend' ); ?>
				<input type="hidden" name="action" value="bastion_prepend"><input type="hidden" name="do" value="uninstall">
				<button class="button"><?php esc_html_e( 'Remove extended protection', 'bastion-security' ); ?></button>
			</form>
		<?php else : ?>
			<form method="post" action="<?php echo esc_url( $post_url ); ?>">
				<?php wp_nonce_field( 'bastion_prepend' ); ?>
				<input type="hidden" name="action" value="bastion_prepend"><input type="hidden" name="do" value="install">
				<button class="button button-primary"><?php esc_html_e( 'Enable extended protection', 'bastion-security' ); ?></button>
				<p class="description">
					<?php
					echo esc_html(
						'htaccess' === $method
							? __( 'Adds an auto_prepend_file rule to .htaccess (Apache/LiteSpeed).', 'bastion-security' )
							: __( 'Adds an auto_prepend_file rule to .user.ini (PHP-FPM / CGI).', 'bastion-security' )
					);
					?>
					<?php esc_html_e( 'In an emergency, delete bastion-waf-prepend.php from the site root to bypass it.', 'bastion-security' ); ?>
				</p>
			</form>
		<?php endif; ?>
	</section>

	<section class="bastion-card">
		<h2><?php esc_html_e( 'Your connection', 'bastion-security' ); ?></h2>
		<dl class="bastion-dl">
			<dt><?php esc_html_e( 'Your IP as seen by the firewall', 'bastion-security' ); ?></dt><dd class="code"><?php echo esc_html( $my_ip ); ?></dd>
			<dt><?php esc_html_e( 'Raw REMOTE_ADDR', 'bastion-security' ); ?></dt><dd class="code"><?php echo esc_html( isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '' ); ?></dd>
			<?php if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : ?>
				<dt>CF-Connecting-IP</dt><dd class="code"><?php echo esc_html( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) ); ?></dd>
			<?php endif; ?>
			<?php if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : ?>
				<dt>X-Forwarded-For</dt><dd class="code"><?php echo esc_html( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) ); ?></dd>
			<?php endif; ?>
			<dt><?php esc_html_e( 'Country', 'bastion-security' ); ?></dt><dd><?php echo esc_html( Bastion_Waf::instance()->country() ? Bastion_Waf::instance()->country() : __( 'Unknown (needs Cloudflare or GeoIP)', 'bastion-security' ) ); ?></dd>
		</dl>
		<?php if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) && 'auto' === Bastion_Settings::get( 'ip_mode' ) && empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : ?>
			<p class="bastion-note"><?php esc_html_e( 'Your site seems to be behind a proxy or load balancer. If every visitor shows the same IP in the activity log, set "How to get visitor IPs" to X-Forwarded-For and add the proxy to Trusted proxies.', 'bastion-security' ); ?></p>
		<?php endif; ?>
		<?php if ( ! in_array( $my_ip, (array) Bastion_Settings::get( 'ip_allowlist' ), true ) ) : ?>
			<form method="post" action="<?php echo esc_url( $post_url ); ?>">
				<?php wp_nonce_field( 'bastion_allow_my_ip' ); ?>
				<input type="hidden" name="action" value="bastion_allow_my_ip"><input type="hidden" name="return" value="bastion-firewall">
				<button class="button"><?php esc_html_e( 'Allowlist my IP', 'bastion-security' ); ?></button>
			</form>
		<?php endif; ?>
	</section>
</div>

<section class="bastion-card">
	<h2><?php esc_html_e( 'Firewall settings', 'bastion-security' ); ?></h2>
	<?php Bastion_Admin::form_open( 'firewall' ); ?>
	<div class="bastion-fields">
		<?php
		foreach ( array( 'waf_enabled', 'waf_mode', 'waf_block_bad_ua', 'waf_block_probes', 'waf_block_php_uploads', 'auto_block_threshold', 'auto_block_minutes', 'rate_limit_rpm', 'rate_limit_minutes', 'rate_404_per_min', 'ip_mode', 'trusted_proxies', 'ip_allowlist', 'ip_blocklist', 'country_block', 'country_scope' ) as $k ) {
			Bastion_Admin::field( $k );
		}
		?>
	</div>
	<?php Bastion_Admin::form_close(); ?>
</section>

<div class="bastion-grid bastion-grid--2">
	<section class="bastion-card">
		<h2><?php esc_html_e( 'Blocked right now', 'bastion-security' ); ?> <span class="bastion-count"><?php echo count( $blocks ); ?></span></h2>
		<form method="post" action="<?php echo esc_url( $post_url ); ?>" class="bastion-inline-form">
			<?php wp_nonce_field( 'bastion_block_ip' ); ?>
			<input type="hidden" name="action" value="bastion_block_ip"><input type="hidden" name="return" value="bastion-firewall">
			<input type="text" name="ip" placeholder="<?php esc_attr_e( 'IP address', 'bastion-security' ); ?>" aria-label="<?php esc_attr_e( 'IP address to block', 'bastion-security' ); ?>" required class="regular-text bastion-ip-input">
			<select name="minutes" aria-label="<?php esc_attr_e( 'Block for', 'bastion-security' ); ?>">
				<option value="60"><?php esc_html_e( '1 hour', 'bastion-security' ); ?></option>
				<option value="1440"><?php esc_html_e( '1 day', 'bastion-security' ); ?></option>
				<option value="10080" selected><?php esc_html_e( '7 days', 'bastion-security' ); ?></option>
				<option value="43200"><?php esc_html_e( '30 days', 'bastion-security' ); ?></option>
				<option value="0"><?php esc_html_e( 'Permanently', 'bastion-security' ); ?></option>
			</select>
			<button class="button"><?php esc_html_e( 'Block', 'bastion-security' ); ?></button>
		</form>
		<?php if ( ! $blocks ) : ?>
			<p class="bastion-empty"><?php esc_html_e( 'No temporary blocks.', 'bastion-security' ); ?></p>
		<?php else : ?>
			<table class="bastion-table">
				<thead><tr><th><?php esc_html_e( 'IP', 'bastion-security' ); ?></th><th><?php esc_html_e( 'Reason', 'bastion-security' ); ?></th><th><?php esc_html_e( 'Ends', 'bastion-security' ); ?></th><th></th></tr></thead>
				<tbody>
				<?php foreach ( array_slice( $blocks, 0, 100 ) as $b ) : ?>
					<tr>
						<td class="code"><?php echo esc_html( $b['ip'] ); ?><?php echo 'login' === $b['scope'] ? ' <span class="bastion-pill">' . esc_html__( 'login only', 'bastion-security' ) . '</span>' : ''; ?></td>
						<td><?php echo esc_html( $b['reason'] ); ?></td>
						<td><?php echo $b['until'] ? esc_html( sprintf( __( 'in %s', 'bastion-security' ), human_time_diff( $b['until'] ) ) ) : esc_html__( 'never', 'bastion-security' ); ?></td>
						<td class="actions">
							<form method="post" action="<?php echo esc_url( $post_url ); ?>">
								<?php wp_nonce_field( 'bastion_unblock_ip' ); ?>
								<input type="hidden" name="action" value="bastion_unblock_ip"><input type="hidden" name="return" value="bastion-firewall">
								<input type="hidden" name="ip" value="<?php echo esc_attr( $b['ip'] ); ?>">
								<button class="button button-small"><?php esc_html_e( 'Unblock', 'bastion-security' ); ?></button>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</section>

	<section class="bastion-card">
		<h2><?php esc_html_e( 'Rules', 'bastion-security' ); ?></h2>
		<form method="post" action="<?php echo esc_url( $post_url ); ?>">
			<?php wp_nonce_field( 'bastion_rules' ); ?>
			<input type="hidden" name="action" value="bastion_rules">
			<div class="bastion-rules">
				<?php foreach ( $rules as $id => $r ) : ?>
					<label><input type="checkbox" name="rules[]" value="<?php echo esc_attr( $id ); ?>" <?php checked( ! in_array( $id, $disabled, true ) ); ?>> <span><?php echo esc_html( $r['desc'] ); ?></span> <code><?php echo esc_html( $id ); ?></code></label>
				<?php endforeach; ?>
			</div>
			<label class="bastion-label" for="bastion-exceptions"><?php esc_html_e( 'Exceptions', 'bastion-security' ); ?></label>
			<textarea id="bastion-exceptions" name="exceptions" rows="5" class="large-text code"><?php
			foreach ( (array) Bastion_Settings::get( 'param_allowlist' ) as $row ) {
				echo esc_textarea( implode( ' | ', (array) $row ) ) . "\n";
			}
			?></textarea>
			<p class="description"><?php esc_html_e( 'One per line: path | parameter | rule. Use * as a wildcard; a path ending in * matches its prefix. Example: /wp-json/my-plugin/* | json:content | xss-tags', 'bastion-security' ); ?></p>
			<p><button class="button"><?php esc_html_e( 'Save rules', 'bastion-security' ); ?></button></p>
		</form>
	</section>
</div>

<section class="bastion-card">
	<h2><?php esc_html_e( 'Recent firewall activity', 'bastion-security' ); ?></h2>
	<?php if ( ! $events['rows'] ) : ?>
		<p class="bastion-empty"><?php esc_html_e( 'No blocked requests yet. They will appear here as soon as bots find your site.', 'bastion-security' ); ?></p>
	<?php else : ?>
		<div class="bastion-table-wrap">
		<table class="bastion-table">
			<thead><tr><th><?php esc_html_e( 'When', 'bastion-security' ); ?></th><th><?php esc_html_e( 'IP', 'bastion-security' ); ?></th><th><?php esc_html_e( 'What', 'bastion-security' ); ?></th><th><?php esc_html_e( 'Request', 'bastion-security' ); ?></th><th></th></tr></thead>
			<tbody>
			<?php
			foreach ( $events['rows'] as $e ) :
				$d = json_decode( (string) $e->data, true );
				$d = is_array( $d ) ? $d : array();
				?>
				<tr>
					<td title="<?php echo esc_attr( wp_date( 'Y-m-d H:i:s', $e->created ) ); ?>"><?php echo esc_html( human_time_diff( $e->created ) ); ?></td>
					<td class="code"><a href="<?php echo esc_url( admin_url( 'admin.php?page=bastion-activity&ip=' . rawurlencode( $e->ip ) ) ); ?>"><?php echo esc_html( $e->ip ); ?></a><?php echo ! empty( $d['cc'] ) ? ' <small>' . esc_html( $d['cc'] ) . '</small>' : ''; ?></td>
					<td><?php echo Bastion_Admin::severity_badge( $e->severity ); // phpcs:ignore ?> <?php echo esc_html( $e->message ); ?><?php if ( ! empty( $d['param'] ) ) : ?><br><small class="code"><?php echo esc_html( $d['param'] ); ?> = <?php echo esc_html( isset( $d['match'] ) ? $d['match'] : '' ); ?></small><?php endif; ?></td>
					<td class="code bastion-trunc"><?php echo esc_html( ( isset( $d['method'] ) ? $d['method'] . ' ' : '' ) . ( isset( $d['uri'] ) ? $d['uri'] : '' ) ); ?></td>
					<td class="actions">
						<?php if ( ! empty( $d['rule'] ) && 'upload-php' !== $d['rule'] ) : ?>
							<form method="post" action="<?php echo esc_url( $post_url ); ?>">
								<?php wp_nonce_field( 'bastion_allow_param' ); ?>
								<input type="hidden" name="action" value="bastion_allow_param"><input type="hidden" name="return" value="bastion-firewall">
								<input type="hidden" name="event" value="<?php echo (int) $e->id; ?>">
								<button class="button button-small" title="<?php esc_attr_e( 'Stop blocking this rule for this parameter on this path (use for false positives)', 'bastion-security' ); ?>"><?php esc_html_e( 'Allow', 'bastion-security' ); ?></button>
							</form>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		</div>
	<?php endif; ?>
</section>
