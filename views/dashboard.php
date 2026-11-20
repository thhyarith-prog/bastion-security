<?php
/**
 * Dashboard.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

$checks   = Bastion_Hardening::checks();
$counts   = Bastion_Scanner::issue_counts();
$score    = Bastion_Hardening::score( $checks, $counts );
$grade    = $score >= 90 ? 'A' : ( $score >= 75 ? 'B' : ( $score >= 60 ? 'C' : ( $score >= 40 ? 'D' : 'F' ) ) );
$tone     = $score >= 75 ? 'good' : ( $score >= 50 ? 'warn' : 'bad' );
$now      = time();
$attacks1 = Bastion_Events::count_since( Bastion_Events::ATTACK_TYPES, $now - DAY_IN_SECONDS );
$attacks7 = Bastion_Events::count_since( Bastion_Events::ATTACK_TYPES, $now - WEEK_IN_SECONDS );
$fails1   = Bastion_Events::count_since( array( 'login_failed' ), $now - DAY_IN_SECONDS );
$blocks   = Bastion_Firewall::active_blocks();
$series   = Bastion_Events::daily_series( 14 );
$top      = Bastion_Events::top_ips( $now - WEEK_IN_SECONDS );
$status   = Bastion_Firewall::status();
$last     = (int) get_option( 'bastion_last_scan_completed' );
$open     = $counts[1] + $counts[2] + $counts[3] + $counts[4];
$serious  = $counts[3] + $counts[4];
$recent   = Bastion_Events::query( array( 'min_severity' => 2, 'per_page' => 8 ) );

$status_labels = array(
	'extended' => array( __( 'Extended', 'bastion-security' ), 'good', __( 'Runs before WordPress loads.', 'bastion-security' ) ),
	'pending'  => array( __( 'Activating', 'bastion-security' ), 'warn', __( 'Waiting for the server to load the new configuration (up to 5 minutes).', 'bastion-security' ) ),
	'stuck'    => array( __( 'Standard', 'bastion-security' ), 'good', __( 'Runs before other plugins load. Extended mode is set up, but this server has not applied it.', 'bastion-security' ) ),
	'standard' => array( __( 'Standard', 'bastion-security' ), 'good', __( 'Runs before other plugins load.', 'bastion-security' ) ),
	'basic'    => array( __( 'Basic', 'bastion-security' ), 'warn', __( 'The early loader is missing; running inside the plugin.', 'bastion-security' ) ),
	'disabled' => array( __( 'Off', 'bastion-security' ), 'bad', __( 'The firewall is disabled.', 'bastion-security' ) ),
);
$st = $status_labels[ $status ];

usort(
	$checks,
	function ( $a, $b ) {
		$order = array( 'fail' => 0, 'warn' => 1, 'pass' => 2 );
		return $order[ $a['status'] ] <=> $order[ $b['status'] ] ?: $b['weight'] <=> $a['weight'];
	}
);
$failing = array_filter(
	$checks,
	function ( $c ) {
		return 'pass' !== $c['status'];
	}
);
?>
<div class="bastion-grid bastion-grid--hero">
	<section class="bastion-card bastion-score bastion-score--<?php echo esc_attr( $tone ); ?>">
		<div class="bastion-ring" style="--p:<?php echo (int) $score; ?>" role="img" aria-label="<?php echo esc_attr( sprintf( __( 'Security score %d out of 100', 'bastion-security' ), $score ) ); ?>">
			<span class="bastion-ring__grade"><?php echo esc_html( $grade ); ?></span>
			<span class="bastion-ring__num"><?php echo (int) $score; ?>/100</span>
		</div>
		<div>
			<h2><?php esc_html_e( 'Security score', 'bastion-security' ); ?></h2>
			<p>
				<?php
				if ( $serious ) {
					echo esc_html( sprintf( _n( '%d serious issue needs your attention.', '%d serious issues need your attention.', $serious, 'bastion-security' ), $serious ) );
				} elseif ( $failing ) {
					echo esc_html( sprintf( _n( '%d recommendation left to reach full protection.', '%d recommendations left to reach full protection.', count( $failing ), 'bastion-security' ), count( $failing ) ) );
				} else {
					esc_html_e( 'Everything checks out. Nice work.', 'bastion-security' );
				}
				?>
			</p>
			<p class="bastion-actions">
				<a class="button button-primary" href="<?php echo esc_url( admin_url( 'admin.php?page=bastion-scanner' ) ); ?>"><?php echo $last ? esc_html__( 'View scan results', 'bastion-security' ) : esc_html__( 'Run first scan', 'bastion-security' ); ?></a>
				<?php if ( ! Bastion_Two_Factor::is_enabled( get_current_user_id() ) ) : ?>
					<a class="button" href="<?php echo esc_url( admin_url( 'profile.php#bastion-2fa' ) ); ?>"><?php esc_html_e( 'Set up two-factor', 'bastion-security' ); ?></a>
				<?php endif; ?>
			</p>
		</div>
	</section>

	<section class="bastion-stats">
		<div class="bastion-stat"><span class="bastion-stat__num"><?php echo esc_html( number_format_i18n( $attacks1 ) ); ?></span><span class="bastion-stat__label"><?php esc_html_e( 'Attacks blocked (24h)', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php echo esc_html( sprintf( __( '%s this week', 'bastion-security' ), number_format_i18n( $attacks7 ) ) ); ?></span></div>
		<div class="bastion-stat"><span class="bastion-stat__num"><?php echo esc_html( number_format_i18n( $fails1 ) ); ?></span><span class="bastion-stat__label"><?php esc_html_e( 'Failed logins (24h)', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php echo esc_html( sprintf( _n( '%d IP blocked now', '%d IPs blocked now', count( $blocks ), 'bastion-security' ), count( $blocks ) ) ); ?></span></div>
		<div class="bastion-stat"><span class="bastion-stat__num <?php echo $serious ? 'is-bad' : ''; ?>"><?php echo (int) $open; ?></span><span class="bastion-stat__label"><?php esc_html_e( 'Open scan issues', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php echo $last ? esc_html( sprintf( __( 'Last scan %s ago', 'bastion-security' ), human_time_diff( $last ) ) ) : esc_html__( 'Never scanned', 'bastion-security' ); ?></span></div>
		<div class="bastion-stat"><span class="bastion-pill bastion-pill--<?php echo esc_attr( $st[1] ); ?>"><?php echo esc_html( $st[0] ); ?></span><span class="bastion-stat__label"><?php esc_html_e( 'Firewall', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php echo esc_html( $st[2] ); ?></span></div>
	</section>
</div>

<div class="bastion-grid bastion-grid--2">
	<section class="bastion-card">
		<h2><?php esc_html_e( 'Last 14 days', 'bastion-security' ); ?></h2>
		<?php
		$max = 1;
		foreach ( $series as $d ) {
			$max = max( $max, $d['attacks'] + $d['logins'] );
		}
		$w   = 100 / count( $series );
		?>
		<div class="bastion-chart" role="img" aria-label="<?php esc_attr_e( 'Blocked attacks and failed logins per day', 'bastion-security' ); ?>">
			<svg viewBox="0 0 100 40" preserveAspectRatio="none" aria-hidden="true">
				<?php foreach ( $series as $i => $d ) : ?>
					<?php
					$ha = 38 * $d['attacks'] / $max;
					$hl = 38 * $d['logins'] / $max;
					$x  = $i * $w + $w * 0.15;
					?>
					<rect class="bar-attacks" x="<?php echo esc_attr( round( $x, 2 ) ); ?>" y="<?php echo esc_attr( round( 40 - $ha, 2 ) ); ?>" width="<?php echo esc_attr( round( $w * 0.7, 2 ) ); ?>" height="<?php echo esc_attr( round( $ha, 2 ) ); ?>"><title><?php echo esc_html( wp_date( 'M j', $d['day'] ) . ': ' . $d['attacks'] . ' attacks, ' . $d['logins'] . ' failed logins' ); ?></title></rect>
					<rect class="bar-logins" x="<?php echo esc_attr( round( $x, 2 ) ); ?>" y="<?php echo esc_attr( round( 40 - $ha - $hl, 2 ) ); ?>" width="<?php echo esc_attr( round( $w * 0.7, 2 ) ); ?>" height="<?php echo esc_attr( round( $hl, 2 ) ); ?>"><title><?php echo esc_html( wp_date( 'M j', $d['day'] ) . ': ' . $d['attacks'] . ' attacks, ' . $d['logins'] . ' failed logins' ); ?></title></rect>
				<?php endforeach; ?>
			</svg>
			<div class="bastion-chart__axis"><span><?php echo esc_html( wp_date( 'M j', $series[0]['day'] ) ); ?></span><span><?php esc_html_e( 'Today', 'bastion-security' ); ?></span></div>
			<div class="bastion-legend"><span class="k-attacks"><?php esc_html_e( 'Blocked attacks', 'bastion-security' ); ?></span><span class="k-logins"><?php esc_html_e( 'Failed logins', 'bastion-security' ); ?></span><span class="bastion-muted"><?php echo esc_html( sprintf( __( 'Peak: %s/day', 'bastion-security' ), number_format_i18n( $max ) ) ); ?></span></div>
		</div>
	</section>

	<section class="bastion-card">
		<h2><?php esc_html_e( 'Top offending IPs (7 days)', 'bastion-security' ); ?></h2>
		<?php if ( ! $top ) : ?>
			<p class="bastion-empty"><?php esc_html_e( 'No attacks recorded yet.', 'bastion-security' ); ?></p>
		<?php else : ?>
			<table class="bastion-table">
				<thead><tr><th><?php esc_html_e( 'IP', 'bastion-security' ); ?></th><th class="num"><?php esc_html_e( 'Events', 'bastion-security' ); ?></th><th><?php esc_html_e( 'Last seen', 'bastion-security' ); ?></th><th></th></tr></thead>
				<tbody>
				<?php
				$storage = Bastion_Firewall::storage();
				foreach ( $top as $row ) :
					$blocked = $storage->get_block( $row->ip ) || Bastion_IP::in_list( $row->ip, (array) Bastion_Settings::get( 'ip_blocklist' ) );
					$is_me   = Bastion_Waf::instance()->ip === $row->ip;
					?>
					<tr>
						<td><a class="code" href="<?php echo esc_url( admin_url( 'admin.php?page=bastion-activity&ip=' . rawurlencode( $row->ip ) ) ); ?>"><?php echo esc_html( $row->ip ); ?></a></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $row->hits ) ); ?></td>
						<td><?php echo esc_html( sprintf( __( '%s ago', 'bastion-security' ), human_time_diff( $row->last_seen ) ) ); ?></td>
						<td class="actions">
							<?php if ( $is_me ) : ?>
								<span class="bastion-pill"><?php esc_html_e( 'You', 'bastion-security' ); ?></span>
							<?php elseif ( $blocked ) : ?>
								<span class="bastion-pill bastion-pill--bad"><?php esc_html_e( 'Blocked', 'bastion-security' ); ?></span>
							<?php else : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<?php wp_nonce_field( 'bastion_block_ip' ); ?>
									<input type="hidden" name="action" value="bastion_block_ip"><input type="hidden" name="return" value="bastion">
									<input type="hidden" name="ip" value="<?php echo esc_attr( $row->ip ); ?>"><input type="hidden" name="minutes" value="10080">
									<button class="button button-small"><?php esc_html_e( 'Block 7 days', 'bastion-security' ); ?></button>
								</form>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</section>
</div>

<div class="bastion-grid bastion-grid--2">
	<section class="bastion-card">
		<h2><?php esc_html_e( 'Security checklist', 'bastion-security' ); ?></h2>
		<ul class="bastion-checklist">
			<?php foreach ( $checks as $c ) : ?>
				<li class="is-<?php echo esc_attr( $c['status'] ); ?>">
					<span class="bastion-check-icon" aria-hidden="true"></span>
					<div>
						<strong><?php echo esc_html( $c['title'] ); ?></strong>
						<?php if ( 'pass' !== $c['status'] ) : ?>
							<p><?php echo esc_html( $c['detail'] ); ?>
							<?php if ( $c['fix'] ) : ?>
								<?php if ( 0 === strpos( $c['fix'], 'http' ) ) : ?>
									<a href="<?php echo esc_url( $c['fix'] ); ?>"><?php esc_html_e( 'Fix', 'bastion-security' ); ?> →</a>
								<?php else : ?>
									<em><?php echo esc_html( $c['fix'] ); ?></em>
								<?php endif; ?>
							<?php endif; ?>
							</p>
						<?php endif; ?>
					</div>
					<span class="screen-reader-text"><?php echo esc_html( $c['status'] ); ?></span>
				</li>
			<?php endforeach; ?>
		</ul>
	</section>

	<section class="bastion-card">
		<h2><?php esc_html_e( 'Recent security events', 'bastion-security' ); ?></h2>
		<?php if ( ! $recent['rows'] ) : ?>
			<p class="bastion-empty"><?php esc_html_e( 'Nothing to report yet.', 'bastion-security' ); ?></p>
		<?php else : ?>
			<ul class="bastion-feed">
				<?php foreach ( $recent['rows'] as $e ) : ?>
					<li>
						<?php echo Bastion_Admin::severity_badge( $e->severity ); // phpcs:ignore ?>
						<div>
							<span><?php echo esc_html( $e->message ); ?></span>
							<small><?php echo esc_html( sprintf( __( '%1$s ago · %2$s', 'bastion-security' ), human_time_diff( $e->created ), $e->ip ? $e->ip : $e->username ) ); ?></small>
						</div>
					</li>
				<?php endforeach; ?>
			</ul>
			<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=bastion-activity' ) ); ?>"><?php esc_html_e( 'Full activity log', 'bastion-security' ); ?> →</a></p>
		<?php endif; ?>
	</section>
</div>
