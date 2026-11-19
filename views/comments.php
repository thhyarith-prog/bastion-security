<?php
/**
 * Comments screen: the spam shield's settings, what it caught and the clean-up tool.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

$now      = time();
$counts   = Bastion_Comments::counts();
$blocked1 = Bastion_Events::count_since( array( 'comment_blocked', 'comment_spam' ), $now - DAY_IN_SECONDS );
$blocked7 = Bastion_Events::count_since( array( 'comment_blocked', 'comment_spam' ), $now - WEEK_IN_SECONDS );
$would7   = Bastion_Events::count_since( array( 'comment_would_block' ), $now - WEEK_IN_SECONDS );
$recent   = Bastion_Events::query( array( 'group' => 'comments', 'per_page' => 12 ) );
$top      = Bastion_Events::top_ips( $now - WEEK_IN_SECONDS, 6, array( 'comment_blocked', 'comment_spam' ) );
$mode     = Bastion_Comments::mode();
$modes    = array(
	'on'  => array( __( 'On', 'bastion-security' ), 'good' ),
	'log' => array( __( 'Watching', 'bastion-security' ), 'warn' ),
	'off' => array( __( 'Off', 'bastion-security' ), 'bad' ),
);
?>
<section class="bastion-stats bastion-stats--4">
	<div class="bastion-stat"><span class="bastion-pill bastion-pill--<?php echo esc_attr( $modes[ $mode ][1] ); ?>"><?php echo esc_html( $modes[ $mode ][0] ); ?></span><span class="bastion-stat__label"><?php esc_html_e( 'Spam shield', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php echo 'log' === $mode ? esc_html( sprintf( /* translators: %s: number */ __( 'Would have stopped %s this week', 'bastion-security' ), number_format_i18n( $would7 ) ) ) : esc_html__( 'No CAPTCHA, nothing sent to other servers', 'bastion-security' ); ?></span></div>
	<div class="bastion-stat"><span class="bastion-stat__num"><?php echo esc_html( number_format_i18n( $blocked1 ) ); ?></span><span class="bastion-stat__label"><?php esc_html_e( 'Spam stopped (24h)', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php echo esc_html( sprintf( /* translators: %s: number */ __( '%s this week', 'bastion-security' ), number_format_i18n( $blocked7 ) ) ); ?></span></div>
	<div class="bastion-stat"><span class="bastion-stat__num <?php echo $counts['pending'] > 50 ? 'is-bad' : ''; ?>"><?php echo esc_html( number_format_i18n( $counts['pending'] ) ); ?></span><span class="bastion-stat__label"><?php esc_html_e( 'Waiting for approval', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><a href="<?php echo esc_url( admin_url( 'edit-comments.php?comment_status=moderated' ) ); ?>"><?php esc_html_e( 'Review comments', 'bastion-security' ); ?></a></span></div>
	<div class="bastion-stat"><span class="bastion-stat__num"><?php echo esc_html( number_format_i18n( $counts['spam'] ) ); ?></span><span class="bastion-stat__label"><?php esc_html_e( 'In the spam folder', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php echo esc_html( sprintf( /* translators: %s: number */ __( '%s approved comments', 'bastion-security' ), number_format_i18n( $counts['approved'] ) ) ); ?></span></div>
</section>

<div class="bastion-grid bastion-grid--2">
	<section class="bastion-card">
		<h2><?php esc_html_e( 'Spam shield', 'bastion-security' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Spam bots are stopped before their comment is saved. Comments that only look like spam go to the spam folder, so you can still rescue a real one.', 'bastion-security' ); ?></p>
		<?php Bastion_Admin::form_open( 'comments' ); ?>
		<div class="bastion-fields">
			<?php
			foreach ( array( 'comment_shield', 'comment_honeypot', 'comment_js_token', 'comment_no_js_action', 'comment_min_seconds', 'comment_rate_per_hour', 'comment_autoblock' ) as $k ) {
				Bastion_Admin::field( $k );
			}
			?>
			<h3><?php esc_html_e( 'Spam content', 'bastion-security' ); ?></h3>
			<?php
			foreach ( array( 'comment_max_links', 'comment_blocklist', 'comment_block_scripts', 'comment_remove_url', 'comment_block_pings' ) as $k ) {
				Bastion_Admin::field( $k );
			}
			?>
		</div>
		<?php Bastion_Admin::form_close(); ?>
	</section>

	<div>
		<section class="bastion-card bastion-cleanup" id="cleanup" data-pending="<?php echo (int) $counts['pending']; ?>" data-spam="<?php echo (int) $counts['spam']; ?>">
			<h2><?php esc_html_e( 'Clean up old spam', 'bastion-security' ); ?></h2>
			<?php if ( ! $counts['pending'] && ! $counts['spam'] ) : ?>
				<p class="bastion-empty"><?php esc_html_e( 'Nothing to clean up: no comments are waiting and the spam folder is empty.', 'bastion-security' ); ?></p>
			<?php else : ?>
				<p><?php esc_html_e( 'Check every comment waiting for approval for the signs of spam: links back to a website with generic praise, web addresses as names, spam words, too many links, old pingbacks. Comments that look real stay waiting for you.', 'bastion-security' ); ?></p>
				<div class="bastion-actions">
					<?php if ( $counts['pending'] ) : ?>
						<button type="button" class="button button-primary bastion-cleanup__check"><?php esc_html_e( 'Check waiting comments', 'bastion-security' ); ?></button>
						<button type="button" class="button bastion-cleanup__apply" hidden><?php esc_html_e( 'Move them to spam', 'bastion-security' ); ?></button>
					<?php endif; ?>
					<button type="button" class="button bastion-cleanup__empty" <?php echo $counts['spam'] ? '' : 'hidden'; ?>><?php esc_html_e( 'Empty the spam folder', 'bastion-security' ); ?></button>
				</div>
				<div class="bastion-progress" hidden><div class="bastion-progress__bar"><span></span></div></div>
				<p class="bastion-cleanup__status" role="status" aria-live="polite"></p>
				<ul class="bastion-feed bastion-cleanup__samples"></ul>
			<?php endif; ?>
		</section>

		<section class="bastion-card">
			<h2><?php esc_html_e( 'Recently caught', 'bastion-security' ); ?></h2>
			<?php if ( ! $recent['rows'] ) : ?>
				<p class="bastion-empty"><?php esc_html_e( 'Nothing caught yet.', 'bastion-security' ); ?></p>
			<?php else : ?>
				<ul class="bastion-feed">
					<?php foreach ( $recent['rows'] as $e ) : ?>
						<?php $d = json_decode( (string) $e->data, true ); ?>
						<li>
							<?php echo Bastion_Admin::severity_badge( $e->severity ); // phpcs:ignore ?>
							<div><span><?php echo esc_html( $e->message ); ?></span><small><?php echo esc_html( trim( sprintf( '%s ago · %s %s', human_time_diff( $e->created ), $e->ip, ! empty( $d['author'] ) ? '· ' . $d['author'] : '' ) ) ); ?></small></div>
						</li>
					<?php endforeach; ?>
				</ul>
				<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=bastion-activity&group=comments' ) ); ?>"><?php esc_html_e( 'See all in the activity log', 'bastion-security' ); ?></a></p>
			<?php endif; ?>
		</section>

		<?php if ( $top ) : ?>
		<section class="bastion-card">
			<h2><?php esc_html_e( 'Busiest spam senders (7 days)', 'bastion-security' ); ?></h2>
			<table class="bastion-table">
				<thead><tr><th><?php esc_html_e( 'IP', 'bastion-security' ); ?></th><th><?php esc_html_e( 'Caught', 'bastion-security' ); ?></th><th><?php esc_html_e( 'Last seen', 'bastion-security' ); ?></th></tr></thead>
				<tbody>
				<?php foreach ( $top as $r ) : ?>
					<tr><td><a href="<?php echo esc_url( admin_url( 'admin.php?page=bastion-activity&ip=' . rawurlencode( $r->ip ) ) ); ?>"><?php echo esc_html( $r->ip ); ?></a></td><td><?php echo esc_html( number_format_i18n( $r->hits ) ); ?></td><td><?php echo esc_html( human_time_diff( $r->last_seen ) ); ?></td></tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</section>
		<?php endif; ?>
	</div>
</div>
