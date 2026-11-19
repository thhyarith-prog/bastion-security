<?php
/**
 * Activity log screen.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.Security.NonceVerification
$group  = isset( $_GET['group'] ) ? sanitize_key( $_GET['group'] ) : '';
$search = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
$ip     = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
$paged  = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
// phpcs:enable
$groups = Bastion_Events::groups();
$res    = Bastion_Events::query(
	array(
		'group'    => $group,
		'search'   => $search,
		'ip'       => $ip,
		'page'     => $paged,
		'per_page' => 50,
	)
);
$base   = admin_url( 'admin.php?page=bastion-activity' );
?>
<section class="bastion-card">
	<div class="bastion-toolbar">
		<nav class="bastion-filter" aria-label="<?php esc_attr_e( 'Filter', 'bastion-security' ); ?>">
			<a href="<?php echo esc_url( $base ); ?>" class="<?php echo '' === $group ? 'is-active' : ''; ?>"><?php esc_html_e( 'All', 'bastion-security' ); ?></a>
			<?php foreach ( $groups as $key => $g ) : ?>
				<a href="<?php echo esc_url( add_query_arg( 'group', $key, $base ) ); ?>" class="<?php echo $key === $group ? 'is-active' : ''; ?>"><?php echo esc_html( $g['label'] ); ?></a>
			<?php endforeach; ?>
		</nav>
		<form method="get" class="bastion-inline-form">
			<input type="hidden" name="page" value="bastion-activity">
			<?php if ( $group ) : ?><input type="hidden" name="group" value="<?php echo esc_attr( $group ); ?>"><?php endif; ?>
			<input type="search" name="s" value="<?php echo esc_attr( $search ); ?>" placeholder="<?php esc_attr_e( 'Search messages, users…', 'bastion-security' ); ?>" aria-label="<?php esc_attr_e( 'Search the activity log', 'bastion-security' ); ?>">
			<input type="text" name="ip" value="<?php echo esc_attr( $ip ); ?>" placeholder="<?php esc_attr_e( 'IP', 'bastion-security' ); ?>" aria-label="<?php esc_attr_e( 'Filter by IP address', 'bastion-security' ); ?>" class="bastion-ip-input">
			<button class="button"><?php esc_html_e( 'Filter', 'bastion-security' ); ?></button>
		</form>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'bastion_export_log' ); ?>
			<input type="hidden" name="action" value="bastion_export_log">
			<input type="hidden" name="group" value="<?php echo esc_attr( $group ); ?>"><input type="hidden" name="s" value="<?php echo esc_attr( $search ); ?>">
			<button class="button"><?php esc_html_e( 'Export CSV', 'bastion-security' ); ?></button>
		</form>
	</div>

	<?php if ( ! $res['rows'] ) : ?>
		<p class="bastion-empty"><?php esc_html_e( 'No matching events.', 'bastion-security' ); ?></p>
	<?php else : ?>
		<div class="bastion-table-wrap">
		<table class="bastion-table bastion-table--log">
			<thead><tr><th><?php esc_html_e( 'Time', 'bastion-security' ); ?></th><th><?php esc_html_e( 'Severity', 'bastion-security' ); ?></th><th><?php esc_html_e( 'Event', 'bastion-security' ); ?></th><th><?php esc_html_e( 'IP', 'bastion-security' ); ?></th><th><?php esc_html_e( 'User', 'bastion-security' ); ?></th></tr></thead>
			<tbody>
			<?php
			foreach ( $res['rows'] as $e ) :
				$d = json_decode( (string) $e->data, true );
				?>
				<tr>
					<td title="<?php echo esc_attr( wp_date( 'Y-m-d H:i:s T', $e->created ) ); ?>"><?php echo esc_html( wp_date( 'M j, H:i', $e->created ) ); ?></td>
					<td><?php echo Bastion_Admin::severity_badge( $e->severity ); // phpcs:ignore ?></td>
					<td>
						<code class="bastion-type"><?php echo esc_html( $e->type ); ?></code> <?php echo esc_html( $e->message ); ?>
						<?php if ( is_array( $d ) && $d ) : ?>
							<details class="bastion-more"><summary><?php esc_html_e( 'Details', 'bastion-security' ); ?></summary>
								<dl class="bastion-dl">
									<?php foreach ( $d as $k => $v ) : ?>
										<dt><?php echo esc_html( $k ); ?></dt><dd class="code"><?php echo esc_html( is_scalar( $v ) ? (string) $v : wp_json_encode( $v ) ); ?></dd>
									<?php endforeach; ?>
								</dl>
							</details>
						<?php endif; ?>
					</td>
					<td class="code"><?php if ( $e->ip ) : ?><a href="<?php echo esc_url( add_query_arg( 'ip', rawurlencode( $e->ip ), $base ) ); ?>"><?php echo esc_html( $e->ip ); ?></a><?php endif; ?></td>
					<td><?php echo esc_html( $e->username ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		</div>
		<?php if ( $res['pages'] > 1 ) : ?>
			<nav class="bastion-pager">
				<?php
				echo wp_kses_post(
					paginate_links(
						array(
							'base'      => add_query_arg( 'paged', '%#%' ),
							'format'    => '',
							'current'   => $paged,
							'total'     => $res['pages'],
							'prev_text' => '‹',
							'next_text' => '›',
						)
					)
				);
				?>
				<span class="bastion-muted"><?php echo esc_html( sprintf( _n( '%s event', '%s events', $res['total'], 'bastion-security' ), number_format_i18n( $res['total'] ) ) ); ?></span>
			</nav>
		<?php endif; ?>
	<?php endif; ?>
</section>
