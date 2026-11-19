<?php
/**
 * Visitors screen: who reads the site, without storing IP addresses.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

$enabled = (bool) Bastion_Settings::get( 'visitors_enabled' );
$range   = isset( $_GET['range'] ) && '7' === $_GET['range'] ? 7 : 30; // phpcs:ignore -- display filter.
$base    = admin_url( 'admin.php?page=bastion-visitors' );

if ( ! $enabled ) : ?>
	<section class="bastion-card bastion-intro">
		<h2><?php esc_html_e( 'See who visits your site', 'bastion-security' ); ?></h2>
		<p><?php esc_html_e( 'Count visitors and page views, see which pages are read, where people come from, their country and device, and who is on the site right now.', 'bastion-security' ); ?></p>
		<ul class="bastion-ticks">
			<li><?php esc_html_e( 'No cookies and no IP addresses are stored: each visitor is counted with a code that changes every day.', 'bastion-security' ); ?></li>
			<li><?php esc_html_e( 'Nothing is sent to another company: the numbers stay in your own database, for 30 days.', 'bastion-security' ); ?></li>
			<li><?php esc_html_e( 'Works with page caching, adds one tiny script and one small request per page view.', 'bastion-security' ); ?></li>
		</ul>
		<?php Bastion_Admin::form_open( 'visitors' ); ?>
			<input type="hidden" name="bastion[visitors_enabled]" value="1">
			<input type="hidden" name="bastion[visitors_respect_dnt]" value="<?php echo Bastion_Settings::get( 'visitors_respect_dnt' ) ? '1' : ''; ?>">
			<input type="hidden" name="bastion[visitors_exclude]" value="<?php echo esc_attr( Bastion_Settings::get( 'visitors_exclude' ) ); ?>">
			<p class="submit"><button type="submit" class="button button-primary button-hero"><?php esc_html_e( 'Start counting visitors', 'bastion-security' ); ?></button></p>
		</form>
	</section>
	<?php
	return;
endif;

$t0        = Bastion_Visitors::day_start();
$y0        = Bastion_Visitors::day_start( 1 );
$today     = Bastion_Visitors::totals( $t0 );
$yest_same = Bastion_Visitors::totals( $y0, $y0 + ( time() - $t0 ) );
$live      = Bastion_Visitors::live();
$series    = Bastion_Visitors::series( $range );
$since     = Bastion_Visitors::day_start( $range - 1 );
$pages     = Bastion_Visitors::top( 'path', $since, 10 );
$refs      = Bastion_Visitors::top( 'ref', $since, 8 );
$countries = Bastion_Visitors::top( 'cc', $since, 8 );
$devices   = Bastion_Visitors::top( 'device', $since, 3 );
$browsers  = Bastion_Visitors::top( 'browser', $since, 6 );
$bots      = Bastion_Visitors::bots_since( $t0 );
$blocked   = Bastion_Events::count_since( Bastion_Events::ATTACK_TYPES, $t0 );
$total     = 0;
foreach ( $series as $d ) {
	$total += $d['views'];
}

$delta = function ( $now, $then ) {
	if ( ! $then ) {
		return $now ? __( 'none at this time yesterday', 'bastion-security' ) : __( 'same as yesterday', 'bastion-security' );
	}
	$p = round( ( $now - $then ) * 100 / $then );
	/* translators: %s: signed percentage */
	return sprintf( __( '%s vs this time yesterday', 'bastion-security' ), ( $p > 0 ? '+' : '' ) . $p . '%' );
};
$table = function ( $title, $rows, $label, $empty, $col_label ) {
	echo '<section class="bastion-card"><h2>' . esc_html( $title ) . '</h2>';
	if ( ! $rows ) {
		echo '<p class="bastion-empty">' . esc_html( $empty ) . '</p></section>';
		return;
	}
	$max = 1;
	foreach ( $rows as $r ) {
		$max = max( $max, (int) $r->views );
	}
	echo '<table class="bastion-table bastion-table--bars"><thead><tr><th>' . esc_html( $col_label ) . '</th><th class="num">' . esc_html__( 'Visitors', 'bastion-security' ) . '</th><th class="num">' . esc_html__( 'Views', 'bastion-security' ) . '</th></tr></thead><tbody>';
	foreach ( $rows as $r ) {
		printf(
			'<tr><td><span class="bastion-bar" style="--w:%1$d%%"></span><span class="bastion-bar__label">%2$s</span></td><td class="num">%3$s</td><td class="num">%4$s</td></tr>',
			(int) round( 100 * (int) $r->views / $max ),
			$label( $r->v ), // phpcs:ignore -- escaped by the label callbacks below.
			esc_html( number_format_i18n( $r->visitors ) ),
			esc_html( number_format_i18n( $r->views ) )
		);
	}
	echo '</tbody></table></section>';
};
?>
<section class="bastion-stats bastion-stats--4 bastion-visitors" data-live="1">
	<div class="bastion-stat"><span class="bastion-stat__num"><span class="bastion-live-dot" aria-hidden="true"></span><span data-v="live"><?php echo esc_html( number_format_i18n( $live['count'] ) ); ?></span></span><span class="bastion-stat__label"><?php esc_html_e( 'On the site now', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php esc_html_e( 'Last 5 minutes, updates every 30 seconds', 'bastion-security' ); ?></span></div>
	<div class="bastion-stat"><span class="bastion-stat__num" data-v="visitors"><?php echo esc_html( number_format_i18n( $today['visitors'] ) ); ?></span><span class="bastion-stat__label"><?php esc_html_e( 'Visitors today', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php echo esc_html( $delta( $today['visitors'], $yest_same['visitors'] ) ); ?></span></div>
	<div class="bastion-stat"><span class="bastion-stat__num" data-v="views"><?php echo esc_html( number_format_i18n( $today['views'] ) ); ?></span><span class="bastion-stat__label"><?php esc_html_e( 'Page views today', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php echo esc_html( $delta( $today['views'], $yest_same['views'] ) ); ?></span></div>
	<div class="bastion-stat"><span class="bastion-stat__num"><?php echo esc_html( number_format_i18n( $blocked ) ); ?></span><span class="bastion-stat__label"><?php esc_html_e( 'Attacks blocked today', 'bastion-security' ); ?></span><span class="bastion-stat__sub"><?php echo esc_html( sprintf( /* translators: %s: number */ __( '%s automated browsers not counted', 'bastion-security' ), number_format_i18n( $bots ) ) ); ?></span></div>
</section>

<div class="bastion-grid bastion-grid--2">
	<section class="bastion-card">
		<div class="bastion-card__head">
			<h2><?php echo esc_html( sprintf( /* translators: %d: days */ __( 'Last %d days', 'bastion-security' ), $range ) ); ?></h2>
			<nav class="bastion-seg" aria-label="<?php esc_attr_e( 'Period', 'bastion-security' ); ?>">
				<a href="<?php echo esc_url( add_query_arg( 'range', '7', $base ) ); ?>" class="<?php echo 7 === $range ? 'is-active' : ''; ?>" <?php echo 7 === $range ? 'aria-current="page"' : ''; ?>>7</a>
				<a href="<?php echo esc_url( $base ); ?>" class="<?php echo 30 === $range ? 'is-active' : ''; ?>" <?php echo 30 === $range ? 'aria-current="page"' : ''; ?>>30</a>
			</nav>
		</div>
		<?php
		$max = 1;
		foreach ( $series as $d ) {
			$max = max( $max, $d['views'] );
		}
		$w = 100 / count( $series );
		?>
		<div class="bastion-chart" role="img" aria-label="<?php esc_attr_e( 'Page views and visitors per day', 'bastion-security' ); ?>">
			<svg viewBox="0 0 100 40" preserveAspectRatio="none" aria-hidden="true">
				<?php foreach ( $series as $i => $d ) : ?>
					<?php
					$hv = 38 * $d['views'] / $max;
					$hu = 38 * $d['visitors'] / $max;
					$x  = $i * $w + $w * 0.15;
					$tt = wp_date( 'M j', $d['ts'] ) . ': ' . $d['visitors'] . ' visitors, ' . $d['views'] . ' views';
					?>
					<rect class="bar-logins" x="<?php echo esc_attr( round( $x, 2 ) ); ?>" y="<?php echo esc_attr( round( 40 - $hv, 2 ) ); ?>" width="<?php echo esc_attr( round( $w * 0.7, 2 ) ); ?>" height="<?php echo esc_attr( round( $hv, 2 ) ); ?>"><title><?php echo esc_html( $tt ); ?></title></rect>
					<rect class="bar-attacks" x="<?php echo esc_attr( round( $x, 2 ) ); ?>" y="<?php echo esc_attr( round( 40 - $hu, 2 ) ); ?>" width="<?php echo esc_attr( round( $w * 0.7, 2 ) ); ?>" height="<?php echo esc_attr( round( $hu, 2 ) ); ?>"><title><?php echo esc_html( $tt ); ?></title></rect>
				<?php endforeach; ?>
			</svg>
			<div class="bastion-chart__axis"><span><?php echo esc_html( wp_date( 'M j', $series[0]['ts'] ) ); ?></span><span><?php esc_html_e( 'Today', 'bastion-security' ); ?></span></div>
			<div class="bastion-legend"><span class="k-attacks"><?php esc_html_e( 'Visitors', 'bastion-security' ); ?></span><span class="k-logins"><?php esc_html_e( 'Page views', 'bastion-security' ); ?></span><span class="bastion-muted"><?php echo esc_html( sprintf( /* translators: %s: number */ __( '%s views in this period', 'bastion-security' ), number_format_i18n( $total ) ) ); ?></span></div>
		</div>
		<?php if ( ! Bastion_Visitors::has_data() ) : ?>
			<p class="bastion-empty"><?php esc_html_e( 'Counting has started. The first visits appear here within a minute; pages your caching plugin already stored count once it refreshes them.', 'bastion-security' ); ?></p>
		<?php endif; ?>
	</section>

	<section class="bastion-card">
		<h2><?php esc_html_e( 'Pages being read now', 'bastion-security' ); ?></h2>
		<ul class="bastion-feed" data-v="pages">
			<?php if ( ! $live['pages'] ) : ?>
				<li class="bastion-empty"><?php esc_html_e( 'Nobody right now.', 'bastion-security' ); ?></li>
			<?php else : ?>
				<?php foreach ( $live['pages'] as $p ) : ?>
					<li><div><span><?php echo esc_html( $p->path ); ?></span><small><?php echo esc_html( sprintf( _n( '%s visitor', '%s visitors', (int) $p->n, 'bastion-security' ), number_format_i18n( $p->n ) ) ); ?></small></div></li>
				<?php endforeach; ?>
			<?php endif; ?>
		</ul>
	</section>
</div>

<div class="bastion-grid bastion-grid--2">
	<?php
	$table(
		__( 'Top pages', 'bastion-security' ),
		$pages,
		function ( $v ) {
			return '<a href="' . esc_url( home_url( $v ) ) . '" target="_blank" rel="noopener">' . esc_html( $v ) . '</a>';
		},
		__( 'No page views yet.', 'bastion-security' ),
		__( 'Page', 'bastion-security' )
	);
	$table(
		__( 'Where visitors come from', 'bastion-security' ),
		$refs,
		function ( $v ) {
			return '' === $v ? esc_html__( 'Direct, bookmarks and apps', 'bastion-security' ) : esc_html( $v );
		},
		__( 'No visits yet.', 'bastion-security' ),
		__( 'Website', 'bastion-security' )
	);
	$table(
		__( 'Countries', 'bastion-security' ),
		$countries,
		function ( $v ) {
			return '' === $v ? esc_html__( 'Unknown', 'bastion-security' ) : esc_html( $v );
		},
		__( 'No visits yet.', 'bastion-security' ),
		__( 'Country', 'bastion-security' )
	);
	?>
	<div>
		<?php
		$table(
			__( 'Devices', 'bastion-security' ),
			$devices,
			function ( $v ) {
				$d = Bastion_Visitors::DEVICES;
				return esc_html( isset( $d[ (int) $v ] ) ? $d[ (int) $v ] : '?' );
			},
			__( 'No visits yet.', 'bastion-security' ),
			__( 'Device', 'bastion-security' )
		);
		$table(
			__( 'Browsers', 'bastion-security' ),
			$browsers,
			function ( $v ) {
				$b = Bastion_Visitors::BROWSERS;
				return esc_html( isset( $b[ (int) $v ] ) ? $b[ (int) $v ] : '?' );
			},
			__( 'No visits yet.', 'bastion-security' ),
			__( 'Browser', 'bastion-security' )
		);
		?>
	</div>
</div>

<?php if ( $countries && 1 === count( $countries ) && '' === $countries[0]->v ) : ?>
	<p class="description"><?php esc_html_e( 'Countries show once your site is behind Cloudflare (free plan) or your host provides a GeoIP module.', 'bastion-security' ); ?></p>
<?php endif; ?>

<section class="bastion-card">
	<h2><?php esc_html_e( 'Visitor counting', 'bastion-security' ); ?></h2>
	<p class="description"><?php esc_html_e( 'No cookies and no IP addresses are stored. Each visitor is counted with a code made with a random key that is replaced every day, so visits can\'t be linked across days; visitors over several days are the sum of each day\'s visitors. Data is kept 30 days. A short note was added to your privacy policy guide (Settings › Privacy).', 'bastion-security' ); ?></p>
	<?php Bastion_Admin::form_open( 'visitors' ); ?>
	<div class="bastion-fields">
		<?php
		foreach ( array( 'visitors_enabled', 'visitors_exclude', 'visitors_respect_dnt' ) as $k ) {
			Bastion_Admin::field( $k );
		}
		?>
	</div>
	<?php Bastion_Admin::form_close(); ?>
</section>
