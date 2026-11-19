<?php
/**
 * Login security screen.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

$events  = Bastion_Events::query( array( 'group' => 'logins', 'per_page' => 20 ) );
$privileged = get_users(
	array(
		'role__in' => array_merge( array( 'administrator' ), (array) Bastion_Settings::get( 'tfa_required_roles' ) ),
		'number'   => 100,
		'fields'   => array( 'ID', 'user_login', 'display_name' ),
	)
);
?>
<div class="bastion-grid bastion-grid--2">
	<section class="bastion-card">
		<h2><?php esc_html_e( 'Brute-force protection', 'bastion-security' ); ?></h2>
		<?php Bastion_Admin::form_open( 'login' ); ?>
		<div class="bastion-fields">
			<?php
			foreach ( array( 'login_max_attempts', 'login_window_minutes', 'login_lockout_minutes', 'login_progressive', 'login_block_usernames', 'login_generic_errors', 'block_user_enum', 'xmlrpc_mode', 'disable_app_passwords', 'lostpassword_limit' ) as $k ) {
				Bastion_Admin::field( $k );
			}
			?>
			<h3><?php esc_html_e( 'Two-factor authentication', 'bastion-security' ); ?></h3>
			<?php
			foreach ( array( 'tfa_required_roles', 'tfa_grace_days', 'tfa_remember_days' ) as $k ) {
				Bastion_Admin::field( $k );
			}
			?>
			<h3><?php esc_html_e( 'Passwords', 'bastion-security' ); ?></h3>
			<?php
			foreach ( array( 'password_roles', 'password_min_length', 'password_breach_check' ) as $k ) {
				Bastion_Admin::field( $k );
			}
			?>
		</div>
		<?php Bastion_Admin::form_close(); ?>
	</section>

	<div>
		<section class="bastion-card">
			<h2><?php esc_html_e( 'Two-factor status', 'bastion-security' ); ?></h2>
			<table class="bastion-table">
				<thead><tr><th><?php esc_html_e( 'User', 'bastion-security' ); ?></th><th><?php esc_html_e( 'Two-factor', 'bastion-security' ); ?></th></tr></thead>
				<tbody>
				<?php foreach ( $privileged as $u ) : ?>
					<tr>
						<td><a href="<?php echo esc_url( get_edit_user_link( $u->ID ) . '#bastion-2fa' ); ?>"><?php echo esc_html( $u->display_name . ' (' . $u->user_login . ')' ); ?></a></td>
						<td><?php echo Bastion_Two_Factor::is_enabled( $u->ID ) ? '<span class="bastion-pill bastion-pill--good">' . esc_html__( 'On', 'bastion-security' ) . '</span>' : '<span class="bastion-pill bastion-pill--bad">' . esc_html__( 'Off', 'bastion-security' ) . '</span>'; ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<p class="description"><?php esc_html_e( 'Each user turns two-factor on from their own profile page. Administrators can turn it off for a user who lost their phone.', 'bastion-security' ); ?></p>
		</section>

		<section class="bastion-card">
			<h2><?php esc_html_e( 'Recent sign-in activity', 'bastion-security' ); ?></h2>
			<?php if ( ! $events['rows'] ) : ?>
				<p class="bastion-empty"><?php esc_html_e( 'No sign-in activity yet.', 'bastion-security' ); ?></p>
			<?php else : ?>
				<ul class="bastion-feed">
					<?php foreach ( $events['rows'] as $e ) : ?>
						<li>
							<?php echo Bastion_Admin::severity_badge( $e->severity ); // phpcs:ignore ?>
							<div><span><?php echo esc_html( $e->message ); ?></span><small><?php echo esc_html( sprintf( '%s ago · %s', human_time_diff( $e->created ), $e->ip ) ); ?></small></div>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</section>
	</div>
</div>
