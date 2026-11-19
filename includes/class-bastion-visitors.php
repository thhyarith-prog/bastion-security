<?php
/**
 * Visitor monitoring without IP addresses or cookies.
 *
 * A tiny script at the end of each page reports the page and where the visitor came from to
 * a REST endpoint once per page view (in the cached HTML too, so Slipstream pages count).
 * Each visitor is counted with a hash of their IP and browser made with a random key that is
 * replaced every day and never kept, so the same person can't be followed from one day to the
 * next and no IP is ever stored. Rows are kept 30 days.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Visitors {

	const KEEP_DAYS = 30;
	const LIVE      = 300;
	const DEVICES   = array( 'Desktop', 'Mobile', 'Tablet' );
	const BROWSERS  = array( 'Other', 'Chrome', 'Safari', 'Firefox', 'Edge', 'Opera', 'Samsung Internet', 'UC Browser' );
	const BOT_UA    = '~bot\b|crawl|spider|slurp|headless|phantom|puppeteer|playwright|selenium|python-|curl/|wget|go-http|java/|okhttp|axios|node-fetch|scrapy|lighthouse|pagespeed|gtmetrix|pingdom|uptime~i';

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'bastion_hits';
	}

	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
		add_action( 'bastion_settings_updated', array( __CLASS__, 'on_settings' ) );
		if ( Bastion_Settings::get( 'visitors_enabled' ) ) {
			add_action( 'wp_footer', array( __CLASS__, 'beacon' ), 99 );
			add_action( 'admin_init', array( __CLASS__, 'privacy_text' ) );
		}
	}

	/** Turning counting on or off changes every page: refresh pages a caching plugin stored. */
	public static function on_settings( $all ) {
		$state = wp_json_encode( array( ! empty( $all['visitors_enabled'] ), isset( $all['visitors_exclude'] ) ? $all['visitors_exclude'] : '', ! empty( $all['visitors_respect_dnt'] ) ) );
		if ( get_option( 'bastion_visitors_state' ) === $state ) {
			return;
		}
		update_option( 'bastion_visitors_state', $state, false );
		if ( class_exists( 'Slipstream_Cache' ) && method_exists( 'Slipstream_Cache', 'purge_all_soon' ) ) {
			Slipstream_Cache::purge_all_soon();
		}
	}

	/* ============================================================== browser */

	private static function excluded() {
		if ( ! is_user_logged_in() ) {
			return false;
		}
		$rule = Bastion_Settings::get( 'visitors_exclude' );
		return 'logged_in' === $rule || ( 'editors' === $rule && current_user_can( 'edit_posts' ) );
	}

	/** The counting script: no cookies, no IDs, one small request per page view. */
	public static function beacon() {
		if ( is_admin() || is_feed() || is_robots() || is_trackback() || is_preview() || is_customize_preview() || self::excluded() ) {
			return;
		}
		$url = rest_url( 'bastion/v1/hit' );
		$dnt = Bastion_Settings::get( 'visitors_respect_dnt' ) ? 1 : 0;
		// Page and referrer travel base64-encoded so the firewall never mistakes a path such as
		// "/edit-wp-config-guide/" for an attack.
		$js = '(function(){try{var n=navigator,w=window;if(' . $dnt . '&&(n.doNotTrack=="1"||w.doNotTrack=="1"||n.globalPrivacyControl))return;'
			. 'if(document.visibilityState=="prerender")return;'
			. 'var e=function(s){try{return btoa(unescape(encodeURIComponent(s)))}catch(x){return""}},r="";'
			. 'try{var u=new URL(document.referrer);if(u.host!==location.host)r=u.host}catch(x){}'
			. 'var d="p="+encodeURIComponent(e(location.pathname))+"&r="+encodeURIComponent(e(r))+"&w="+(w.innerWidth||0)+"&b="+(n.webdriver?1:0),'
			. 'go=function(){var url=' . wp_json_encode( esc_url_raw( $url ) ) . ';if(n.sendBeacon&&n.sendBeacon(url,new Blob([d],{type:"application/x-www-form-urlencoded"})))return;'
			. 'try{fetch(url,{method:"POST",body:d,keepalive:true,credentials:"omit",headers:{"Content-Type":"application/x-www-form-urlencoded"}})}catch(x){}};'
			. 'if(document.readyState=="complete")setTimeout(go,300);else w.addEventListener("load",function(){setTimeout(go,300)})}catch(x){}})();';
		echo '<script data-no-optimize="1" data-cfasync="false" data-slipstream-skip>' . $js . "</script>\n"; // phpcs:ignore -- built from fixed strings and a JSON-encoded URL.
	}

	public static function privacy_text() {
		if ( function_exists( 'wp_add_privacy_policy_content' ) ) {
			wp_add_privacy_policy_content(
				'Bastion Security',
				'<p>' . esc_html__( 'This site counts visits to see which pages are read and where visitors come from. No cookies are set and no IP address is stored: each visitor is counted with a code made from their connection and browser using a random key that is replaced every day, so visits cannot be linked from one day to the next. The page address, the website you came from, your country (when known), device type and browser are kept for 30 days. Browsers that send "Do Not Track" or Global Privacy Control are not counted.', 'bastion-security' ) . '</p>'
			);
		}
	}

	/* =============================================================== server */

	public static function routes() {
		register_rest_route(
			'bastion/v1',
			'/hit',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_hit' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	public static function rest_hit( WP_REST_Request $req ) {
		self::record( $req->get_params() );
		$res = new WP_REST_Response( null, 204 );
		$res->header( 'Cache-Control', 'no-store' );
		return $res;
	}

	private static function decode( $v, $max ) {
		$s = base64_decode( (string) $v, true ); // phpcs:ignore -- the beacon encodes, see beacon().
		return false === $s ? '' : mb_substr( $s, 0, $max );
	}

	/** Today's random key; a new one replaces it at midnight (site time) and the old one is gone. */
	private static function day_key( $day ) {
		$salt = get_option( 'bastion_visit_salt' );
		if ( ! is_array( $salt ) || ! isset( $salt['d'], $salt['s'] ) || (int) $salt['d'] !== $day ) {
			$salt = array( 'd' => $day, 's' => bin2hex( random_bytes( 24 ) ) );
			update_option( 'bastion_visit_salt', $salt, false );
		}
		return $salt['s'];
	}

	public static function classify_ua( $ua ) {
		$device = preg_match( '/iPad|Tablet|Android(?!.*Mobile)|Silk|Kindle/i', $ua ) ? 2 : ( preg_match( '/Mobi|iPhone|iPod|Android.*Mobile|Windows Phone/i', $ua ) ? 1 : 0 );
		$order  = array( 'Edg/' => 4, 'OPR/' => 5, 'Opera' => 5, 'SamsungBrowser' => 6, 'UCBrowser' => 7, 'Firefox/' => 3, 'FxiOS' => 3, 'CriOS' => 1, 'Chrome/' => 1, 'Safari/' => 2 );
		$browser = 0;
		foreach ( $order as $needle => $id ) {
			if ( false !== stripos( $ua, $needle ) ) {
				$browser = $id;
				break;
			}
		}
		return array( $device, $browser );
	}

	public static function record( array $in ) {
		if ( ! Bastion_Settings::get( 'visitors_enabled' ) ) {
			return;
		}
		// Only count reports sent by pages of this site.
		$home   = wp_parse_url( home_url(), PHP_URL_HOST );
		$origin = isset( $_SERVER['HTTP_ORIGIN'] ) ? wp_parse_url( (string) $_SERVER['HTTP_ORIGIN'], PHP_URL_HOST ) : ( isset( $_SERVER['HTTP_REFERER'] ) ? wp_parse_url( (string) $_SERVER['HTTP_REFERER'], PHP_URL_HOST ) : '' ); // phpcs:ignore
		if ( ! $origin || strtolower( (string) $origin ) !== strtolower( (string) $home ) ) {
			return;
		}
		if ( Bastion_Settings::get( 'visitors_respect_dnt' ) && ( ( isset( $_SERVER['HTTP_DNT'] ) && '1' === $_SERVER['HTTP_DNT'] ) || ( isset( $_SERVER['HTTP_SEC_GPC'] ) && '1' === $_SERVER['HTTP_SEC_GPC'] ) ) ) {
			return;
		}
		$waf = Bastion_Waf::instance();
		if ( Bastion_Firewall::storage()->hit( 'vb:' . $waf->ip, 60 ) > 60 ) {
			return;
		}
		$path = self::decode( isset( $in['p'] ) ? $in['p'] : '', 191 );
		if ( '' === $path || '/' !== $path[0] ) {
			return;
		}
		$path = preg_replace( '/[\x00-\x1f\x7f]/', '', $path );
		$ref  = strtolower( self::decode( isset( $in['r'] ) ? $in['r'] : '', 100 ) );
		$ref  = preg_match( '/^[a-z0-9.\-]+(:\d+)?$/', $ref ) ? preg_replace( '/^www\./', '', $ref ) : '';
		$ua   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( (string) $_SERVER['HTTP_USER_AGENT'], 0, 400 ) : ''; // phpcs:ignore
		list( $device, $browser ) = self::classify_ua( $ua );
		$width = isset( $in['w'] ) ? (int) $in['w'] : 0;
		if ( 0 === $device && $width > 0 && $width < 600 ) {
			$device = 1;
		}
		$kind = ( ! empty( $in['b'] ) || '' === $ua || preg_match( self::BOT_UA, $ua ) ) ? 1 : 0;
		$now  = time();
		$day  = (int) wp_date( 'Ymd', $now );
		$vid  = substr( hash_hmac( 'sha256', $waf->ip . '|' . $ua, self::day_key( $day ) ), 0, 16 );
		global $wpdb;
		$wpdb->insert( // phpcs:ignore
			self::table(),
			array(
				'ts'      => $now,
				'day'     => $day,
				'vid'     => $vid,
				'path'    => $path,
				'ref'     => $ref,
				'cc'      => (string) $waf->country(),
				'device'  => $device,
				'browser' => $browser,
				'kind'    => $kind,
			),
			array( '%d', '%d', '%s', '%s', '%s', '%s', '%d', '%d', '%d' )
		);
	}

	public static function purge() {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table() . ' WHERE ts < %d', time() - self::KEEP_DAYS * DAY_IN_SECONDS ) ); // phpcs:ignore
	}

	/* ============================================================== reports */

	/** Midnight in the site's time zone, $ago days back. */
	public static function day_start( $ago = 0 ) {
		$d = new DateTimeImmutable( 'today', wp_timezone() );
		return $ago ? $d->modify( '-' . (int) $ago . ' days' )->getTimestamp() : $d->getTimestamp();
	}

	/** Visitors and views since a time (humans only). */
	public static function totals( $from, $to = null ) {
		global $wpdb;
		$to  = null === $to ? time() + 1 : $to;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT COUNT(*) AS views, COUNT(DISTINCT vid) AS visitors FROM ' . self::table() . ' WHERE ts >= %d AND ts < %d AND kind = 0', $from, $to ) ); // phpcs:ignore
		return array( 'views' => (int) ( $row ? $row->views : 0 ), 'visitors' => (int) ( $row ? $row->visitors : 0 ) );
	}

	public static function live() {
		global $wpdb;
		$since = time() - self::LIVE;
		$count = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(DISTINCT vid) FROM ' . self::table() . ' WHERE ts >= %d AND kind = 0', $since ) ); // phpcs:ignore
		$pages = $wpdb->get_results( $wpdb->prepare( 'SELECT path, COUNT(DISTINCT vid) AS n FROM ' . self::table() . ' WHERE ts >= %d AND kind = 0 GROUP BY path ORDER BY n DESC LIMIT 5', $since ) ); // phpcs:ignore
		return array( 'count' => $count, 'pages' => $pages );
	}

	/** Views and visitors per day for the last $days days (visitors are counted per day). */
	public static function series( $days ) {
		global $wpdb;
		$start = (int) wp_date( 'Ymd', time() - ( $days - 1 ) * DAY_IN_SECONDS );
		$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT day, COUNT(*) AS views, COUNT(DISTINCT vid) AS visitors FROM ' . self::table() . ' WHERE day >= %d AND kind = 0 GROUP BY day', $start ) ); // phpcs:ignore
		$by    = array();
		foreach ( (array) $rows as $r ) {
			$by[ (int) $r->day ] = $r;
		}
		$out = array();
		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$ts    = time() - $i * DAY_IN_SECONDS;
			$d     = (int) wp_date( 'Ymd', $ts );
			$out[] = array( 'ts' => $ts, 'views' => isset( $by[ $d ] ) ? (int) $by[ $d ]->views : 0, 'visitors' => isset( $by[ $d ] ) ? (int) $by[ $d ]->visitors : 0 );
		}
		return $out;
	}

	/**
	 * Top values of one column since a time.
	 *
	 * @param string $col path|ref|cc|device|browser.
	 */
	public static function top( $col, $since, $limit = 10, $kind = 0 ) {
		global $wpdb;
		if ( ! in_array( $col, array( 'path', 'ref', 'cc', 'device', 'browser' ), true ) ) {
			return array();
		}
		return $wpdb->get_results( $wpdb->prepare( "SELECT {$col} AS v, COUNT(*) AS views, COUNT(DISTINCT vid) AS visitors FROM " . self::table() . ' WHERE ts >= %d AND kind = %d GROUP BY v ORDER BY views DESC LIMIT %d', $since, $kind, $limit ) ); // phpcs:ignore -- column from the whitelist above.
	}

	public static function bots_since( $since ) {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . self::table() . ' WHERE ts >= %d AND kind = 1', $since ) ); // phpcs:ignore
	}

	/** Whether any hit has been recorded yet (for the empty state). */
	public static function has_data() {
		global $wpdb;
		return (bool) $wpdb->get_var( 'SELECT id FROM ' . self::table() . ' LIMIT 1' ); // phpcs:ignore
	}
}
