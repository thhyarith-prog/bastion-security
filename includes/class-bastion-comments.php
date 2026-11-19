<?php
/**
 * Comment spam shield: stops comment bots without a CAPTCHA and without sending anything to
 * an outside service.
 *
 * Layers, cheapest first:
 *  - a hidden trap field (honeypot) that people never see and bots fill in;
 *  - a one-time token the comment form fetches from this site when someone starts writing
 *    (assets/comments.js). It is never part of the page HTML, so it works with page caching,
 *    and it carries a server-signed time, so a comment sent seconds after the token is a bot;
 *  - a limit on comments per IP;
 *  - content checks (too many links, spam words, alphabets the site never gets real comments
 *    in, a website link when the field was removed) that send a comment to the spam folder
 *    instead of rejecting it, so a false positive can still be rescued;
 *  - pingbacks and trackbacks off.
 *
 * Hard failures are rejected before anything is stored; soft failures go to spam. Everything
 * is written to the activity log under "Comments". Watch-only mode logs without acting.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Comments {

	const TOKEN_MAX_AGE = 2 * DAY_IN_SECONDS;
	const GRACE         = 12 * HOUR_IN_SECONDS;
	const TYPES         = array( 'comment_blocked', 'comment_spam', 'comment_held', 'comment_would_block', 'spam_cleanup' );

	/** Unicode script classes for the alphabet filter. */
	const SCRIPTS = array(
		'cyrillic'   => '\p{Cyrillic}',
		'han'        => '\p{Han}',
		'hangul'     => '\p{Hangul}',
		'arabic'     => '\p{Arabic}',
		'hebrew'     => '\p{Hebrew}',
		'devanagari' => '\p{Devanagari}',
		'greek'      => '\p{Greek}',
	);

	/** The settings that change what the comment form looks like (a change starts a grace window). */
	const FORM_KEYS = array( 'comment_shield', 'comment_honeypot', 'comment_js_token', 'comment_remove_url' );

	public static function init() {
		add_action( 'bastion_settings_updated', array( __CLASS__, 'on_settings' ) );
		add_action( 'wp_ajax_bastion_ct', array( __CLASS__, 'ajax_token' ) );
		add_action( 'wp_ajax_nopriv_bastion_ct', array( __CLASS__, 'ajax_token' ) );
		if ( 'off' === self::mode() ) {
			return;
		}
		add_filter( 'pre_comment_approved', array( __CLASS__, 'judge' ), 5, 2 );
		add_action( 'comment_form', array( __CLASS__, 'form_fields' ) );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
		add_filter( 'script_loader_tag', array( __CLASS__, 'script_tag' ), 10, 2 );
		add_filter( 'rest_allow_anonymous_comments', '__return_false', 99 );
		if ( Bastion_Settings::get( 'comment_remove_url' ) ) {
			add_filter( 'comment_form_default_fields', array( __CLASS__, 'remove_url_field' ) );
		}
		if ( Bastion_Settings::get( 'comment_block_pings' ) ) {
			add_filter( 'pings_open', '__return_false', 99 );
		}
	}

	public static function mode() {
		$m = (string) Bastion_Settings::get( 'comment_shield' );
		return in_array( $m, array( 'on', 'log', 'off' ), true ) ? $m : 'on';
	}

	/* ============================================================== the form */

	/** The trap field and a note for visitors without JavaScript, inside every comment form. */
	public static function form_fields() {
		if ( Bastion_Settings::get( 'comment_honeypot' ) ) {
			// Off-screen rather than display:none (some bots skip hidden inputs); the name avoids
			// words browsers autofill.
			echo '<p class="bastion-hp" aria-hidden="true" style="position:absolute!important;left:-9999px!important;width:1px;height:1px;overflow:hidden"><label>' . esc_html__( 'Leave this field empty', 'bastion-security' ) . '<input type="text" name="bastion_hp" value="" tabindex="-1" autocomplete="off"></label></p>';
		}
		if ( Bastion_Settings::get( 'comment_js_token' ) && 'reject' === Bastion_Settings::get( 'comment_no_js_action' ) && ! is_user_logged_in() ) {
			echo '<noscript><p class="bastion-nojs">' . esc_html__( 'Please turn on JavaScript to post a comment.', 'bastion-security' ) . '</p></noscript>';
		}
	}

	public static function enqueue() {
		if ( ! Bastion_Settings::get( 'comment_js_token' ) || ! is_singular() || ! comments_open() ) {
			return;
		}
		wp_enqueue_script( 'bastion-comments', BASTION_URL . 'assets/comments.js', array(), BASTION_VERSION, true );
		wp_localize_script(
			'bastion-comments',
			'BastionComments',
			array(
				'ajax'    => admin_url( 'admin-ajax.php' ),
				'post'    => (int) get_queried_object_id(),
				'min'     => (int) Bastion_Settings::get( 'comment_min_seconds' ),
				'posting' => __( 'Posting…', 'bastion-security' ),
			)
		);
	}

	/** Keep page-speed plugins (Slipstream, Rocket Loader…) from delaying the shield's script. */
	public static function script_tag( $tag, $handle ) {
		if ( 'bastion-comments' === $handle && false === strpos( $tag, 'data-no-optimize' ) ) {
			$tag = str_replace( '<script ', '<script data-no-optimize="1" data-cfasync="false" defer ', $tag );
		}
		return $tag;
	}

	public static function remove_url_field( $fields ) {
		unset( $fields['url'] );
		return $fields;
	}

	/* ================================================================ token */

	private static function key() {
		$secret = get_option( 'bastion_secret' );
		if ( ! $secret ) {
			$secret = wp_generate_password( 64, true, true );
			update_option( 'bastion_secret', $secret, false );
		}
		return hash_hmac( 'sha256', 'bastion-comment-token', wp_salt( 'nonce' ) . $secret );
	}

	private static function sign( $ts, $post ) {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( md5( (string) $_SERVER['HTTP_USER_AGENT'] ), 0, 8 ) : ''; // phpcs:ignore
		return substr( hash_hmac( 'sha256', 'ct|' . $ts . '|' . $post . '|' . $ua, self::key() ), 0, 24 );
	}

	public static function make_token( $post ) {
		$ts = time();
		return 'v1.' . $ts . '.' . (int) $post . '.' . self::sign( $ts, (int) $post );
	}

	/** The comment form asks for a token when someone starts writing. Never cached. */
	public static function ajax_token() {
		nocache_headers();
		header( 'Cache-Control: no-store, private' );
		$post = isset( $_POST['p'] ) ? absint( $_POST['p'] ) : 0; // phpcs:ignore -- public endpoint by design; the token is the protection.
		if ( ! $post || ! comments_open( $post ) ) {
			wp_send_json_error( null, 400 );
		}
		wp_send_json_success( array( 't' => self::make_token( $post ) ) );
	}

	/**
	 * @return array [ status: ok|missing|fallback|invalid|young, age ]
	 */
	public static function check_token( $token, $post ) {
		$token = (string) $token;
		if ( '' === $token ) {
			return array( 'missing', 0 );
		}
		if ( 0 === strpos( $token, 'js:' ) ) {
			return array( 'fallback', 0 ); // JavaScript ran but the token request failed.
		}
		$parts = explode( '.', $token );
		if ( 4 !== count( $parts ) || 'v1' !== $parts[0] ) {
			return array( 'invalid', 0 );
		}
		list( , $ts, $for, $sig ) = $parts;
		$ts  = (int) $ts;
		$age = time() - $ts;
		if ( (int) $for !== (int) $post || ! hash_equals( self::sign( $ts, (int) $for ), (string) $sig ) || $age < -60 || $age > self::TOKEN_MAX_AGE ) {
			return array( 'invalid', $age );
		}
		if ( $age < (int) Bastion_Settings::get( 'comment_min_seconds' ) ) {
			return array( 'young', $age );
		}
		return array( 'ok', $age );
	}

	/* ============================================================== judging */

	private static function in_grace() {
		$since = (int) get_option( 'bastion_comment_shield_since' );
		return $since && time() - $since < self::GRACE;
	}

	/**
	 * Decide what happens to a new comment.
	 *
	 * @return array [ verdict: pass|hold|spam|block, reasons[] ]
	 */
	public static function evaluate( array $c ) {
		$reasons = array();
		$type    = isset( $c['comment_type'] ) ? (string) $c['comment_type'] : '';

		if ( in_array( $type, array( 'pingback', 'trackback' ), true ) ) {
			return Bastion_Settings::get( 'comment_block_pings' ) ? array( 'block', array( 'ping' ) ) : array( 'pass', array() );
		}
		$user_id = isset( $c['user_id'] ) ? (int) $c['user_id'] : 0;
		if ( $user_id && user_can( $user_id, 'moderate_comments' ) ) {
			return array( 'pass', array() );
		}

		// ---- hard: these never come from a person using the form.
		if ( Bastion_Settings::get( 'comment_honeypot' ) && isset( $_POST['bastion_hp'] ) && '' !== trim( (string) wp_unslash( $_POST['bastion_hp'] ) ) ) { // phpcs:ignore
			return array( 'block', array( 'honeypot' ) );
		}
		$limit = (int) Bastion_Settings::get( 'comment_rate_per_hour' );
		if ( $limit > 0 && ! $user_id ) {
			$n = Bastion_Firewall::storage()->hit( 'cmt:' . Bastion_Waf::instance()->ip, HOUR_IN_SECONDS );
			if ( $n > $limit ) {
				return array( 'block', array( 'rate' ) );
			}
		}
		$hold = false;
		$form = isset( $_SERVER['SCRIPT_NAME'] ) && 'wp-comments-post.php' === basename( (string) $_SERVER['SCRIPT_NAME'] ); // phpcs:ignore
		if ( $form && ! $user_id && Bastion_Settings::get( 'comment_js_token' ) ) {
			$post             = isset( $c['comment_post_ID'] ) ? (int) $c['comment_post_ID'] : 0;
			$token            = isset( $_POST['bastion_ct'] ) ? sanitize_text_field( wp_unslash( $_POST['bastion_ct'] ) ) : ''; // phpcs:ignore
			list( $status, ) = self::check_token( $token, $post );
			if ( 'missing' === $status ) {
				if ( self::in_grace() || 'hold' === Bastion_Settings::get( 'comment_no_js_action' ) ) {
					$hold      = true;
					$reasons[] = 'no_token';
				} else {
					return array( 'block', array( 'no_token' ) );
				}
			} elseif ( 'fallback' === $status ) {
				$hold      = true;
				$reasons[] = 'token_fallback';
			} elseif ( 'invalid' === $status ) {
				return array( 'block', array( 'bad_token' ) );
			} elseif ( 'young' === $status ) {
				return array( 'block', array( 'too_fast' ) );
			}
		}

		// ---- soft: content that looks like spam goes to the spam folder.
		$content = isset( $c['comment_content'] ) ? (string) $c['comment_content'] : '';
		$author  = isset( $c['comment_author'] ) ? (string) $c['comment_author'] : '';
		$email   = isset( $c['comment_author_email'] ) ? (string) $c['comment_author_email'] : '';
		$url     = isset( $c['comment_author_url'] ) ? (string) $c['comment_author_url'] : '';
		$soft    = self::content_signals( $content, $author . ' ' . $email . ' ' . $url );
		if ( $url && Bastion_Settings::get( 'comment_remove_url' ) && ! self::in_grace() ) {
			$soft[] = 'url';
		}
		if ( $soft ) {
			return array( 'spam', array_merge( $reasons, $soft ) );
		}
		return array( $hold ? 'hold' : 'pass', $reasons );
	}

	/** Content checks shared by new comments and the clean-up tool. */
	public static function content_signals( $content, $who = '' ) {
		$out   = array();
		$max   = (int) Bastion_Settings::get( 'comment_max_links' );
		$links = preg_match_all( '~https?://|<a\s|www\.~i', $content );
		if ( $max > 0 && $links > $max ) {
			$out[] = 'links';
		}
		$text = $content . ' ' . $who;
		foreach ( (array) Bastion_Settings::get( 'comment_blocklist' ) as $word ) {
			$word = trim( (string) $word );
			if ( '' !== $word && preg_match( '/(?<![\p{L}\p{N}])' . preg_quote( $word, '/' ) . '(?![\p{L}\p{N}])/iu', $text ) ) {
				$out[] = 'words';
				break;
			}
		}
		$scripts = (array) Bastion_Settings::get( 'comment_block_scripts' );
		if ( $scripts ) {
			$letters = preg_match_all( '/\p{L}/u', $content );
			if ( $letters >= 8 ) {
				foreach ( $scripts as $s ) {
					if ( isset( self::SCRIPTS[ $s ] ) && preg_match_all( '/' . self::SCRIPTS[ $s ] . '/u', $content ) / $letters > 0.3 ) {
						$out[] = 'script';
						break;
					}
				}
			}
		}
		return $out;
	}

	/** pre_comment_approved: act on the verdict. */
	public static function judge( $approved, $commentdata ) {
		if ( is_wp_error( $approved ) || 'trash' === $approved ) {
			return $approved;
		}
		list( $verdict, $reasons ) = self::evaluate( (array) $commentdata );
		if ( 'pass' === $verdict ) {
			return $approved;
		}
		$mode = self::mode();
		$post = isset( $commentdata['comment_post_ID'] ) ? (int) $commentdata['comment_post_ID'] : 0;
		$data = array(
			'reasons' => $reasons,
			'post'    => $post,
			'author'  => isset( $commentdata['comment_author'] ) ? mb_substr( (string) $commentdata['comment_author'], 0, 80 ) : '',
			'excerpt' => isset( $commentdata['comment_content'] ) ? mb_substr( wp_strip_all_tags( (string) $commentdata['comment_content'] ), 0, 140 ) : '',
		);
		$what = self::describe( $reasons );

		if ( 'log' === $mode ) {
			if ( 'hold' !== $verdict ) {
				Bastion_Events::log( 'comment_would_block', sprintf( 'Would %s a comment: %s', 'block' === $verdict ? 'block' : 'mark as spam', $what ), array( 'severity' => Bastion_Events::INFO, 'data' => $data ) );
			}
			return $approved;
		}
		if ( 'block' === $verdict ) {
			Bastion_Events::log( 'comment_blocked', 'Comment blocked: ' . $what, array( 'severity' => Bastion_Events::LOW, 'data' => $data ) );
			if ( Bastion_Settings::get( 'comment_autoblock' ) ) {
				Bastion_Waf::instance()->count_attack( 1 );
			}
			$msg = in_array( 'rate', $reasons, true )
				? __( 'You are posting comments too quickly. Please wait a while and try again.', 'bastion-security' )
				: ( in_array( 'no_token', $reasons, true )
					? __( 'Your comment could not be posted. Please turn on JavaScript, reload the page and try again.', 'bastion-security' )
					: __( 'Your comment could not be posted. Please reload the page and try again.', 'bastion-security' ) );
			// wp-comments-post.php reads the error data as the HTTP status code.
			return new WP_Error( 'bastion_comment_blocked', $msg, in_array( 'rate', $reasons, true ) ? 429 : 403 );
		}
		if ( 'spam' === $verdict ) {
			Bastion_Events::log( 'comment_spam', 'Comment sent to spam: ' . $what, array( 'severity' => Bastion_Events::LOW, 'data' => $data ) );
			return 'spam';
		}
		Bastion_Events::log( 'comment_held', 'Comment held for moderation: ' . $what, array( 'severity' => Bastion_Events::INFO, 'data' => $data ) );
		return 0;
	}

	public static function describe( array $reasons ) {
		$labels = array(
			'ping'           => 'pingback or trackback',
			'honeypot'       => 'filled the hidden trap field',
			'rate'           => 'too many comments from one IP',
			'no_token'       => 'no browser check (posted directly)',
			'token_fallback' => 'browser check could not reach the site',
			'bad_token'      => 'forged or expired browser check',
			'too_fast'       => 'written faster than a person can type',
			'links'          => 'too many links',
			'words'          => 'contains a spam word',
			'script'         => 'written in a blocked alphabet',
			'url'            => 'sent a website link after the field was removed',
		);
		$out = array();
		foreach ( $reasons as $r ) {
			$out[] = isset( $labels[ $r ] ) ? $labels[ $r ] : $r;
		}
		return implode( ', ', $out );
	}

	/** A change to the form settings: give cached pages time to refresh before enforcing the token. */
	public static function on_settings( $all ) {
		$now  = md5( wp_json_encode( array_intersect_key( (array) $all, array_flip( self::FORM_KEYS ) ) ) );
		$prev = get_option( 'bastion_comment_form_hash' );
		if ( $now === $prev ) {
			return;
		}
		update_option( 'bastion_comment_form_hash', $now, false );
		if ( false === $prev ) {
			return; // First save since the update: the install already started the grace window.
		}
		update_option( 'bastion_comment_shield_since', time(), false );
		if ( class_exists( 'Slipstream_Cache' ) && method_exists( 'Slipstream_Cache', 'purge_all_soon' ) ) {
			Slipstream_Cache::purge_all_soon();
		}
	}

	/* ===================================================== stats & clean-up */

	public static function counts() {
		$c = wp_count_comments();
		return array(
			'pending'  => (int) $c->moderated,
			'spam'     => (int) $c->spam,
			'approved' => (int) $c->approved,
		);
	}

	/**
	 * How spammy a waiting comment looks, for the clean-up tool. 2 or more is spam.
	 *
	 * @param object $row comment row.
	 */
	public static function spam_score( $row ) {
		$score = 0;
		$type  = (string) $row->comment_type;
		if ( in_array( $type, array( 'pingback', 'trackback' ), true ) ) {
			return 3;
		}
		$content = (string) $row->comment_content;
		$author  = trim( (string) $row->comment_author );
		$url     = trim( (string) $row->comment_author_url );
		foreach ( self::content_signals( $content, $author . ' ' . $row->comment_author_email . ' ' . $url ) as $sig ) {
			$score += 'script' === $sig ? 3 : 2;
		}
		// An author "name" that is a web address or a list of keywords.
		if ( preg_match( '~https?://|www\.|\.(com|net|org|ru|info|xyz|online|shop|top|io)\b~i', $author ) || str_word_count( $author ) > 4 ) {
			$score += 2;
		}
		// Generic praise with a link back: the classic SEO comment.
		if ( '' !== $url && preg_match( '/\b(great|nice|awesome|wonderful|informative|helpful|useful|amazing)\b.{0,40}\b(post|article|blog|content|site|read|information|write-?up)\b|\bthanks? (you )?for (sharing|this|the)\b|\bkeep (it )?up\b|\bbookmark/i', $content ) ) {
			$score += 2;
		}
		if ( '' !== $url && preg_match( '~https?://~i', $content ) ) {
			++$score;
		}
		// Mostly in an alphabet the site isn't written in, with a link back: foreign SEO spam.
		if ( '' !== $url ) {
			$letters = preg_match_all( '/\p{L}/u', $content );
			$foreign = preg_match_all( '/[\p{Cyrillic}\p{Han}\p{Hangul}\p{Arabic}\p{Hebrew}\p{Devanagari}\p{Greek}\p{Hiragana}\p{Katakana}]/u', $content );
			if ( $letters >= 8 && $foreign / $letters > 0.5 && ! preg_match( '/^(ru|uk|bg|sr|mk|be|kk|zh|ja|ko|ar|he|fa|hi|el)/', get_locale() ) ) {
				$score += 2;
			}
		}
		if ( strtotime( $row->comment_date_gmt . ' UTC' ) < time() - 30 * DAY_IN_SECONDS ) {
			++$score; // Waited a month without anyone approving it.
		}
		return $score;
	}

	/**
	 * One batch of the clean-up: score waiting comments after $cursor and, when $apply, mark the
	 * spammy ones as spam with one query (no comment hooks, so no call to Akismet's servers).
	 *
	 * @return array [ cursor, scanned, spam, reasons, samples, done ]
	 */
	public static function cleanup_batch( $cursor, $apply, $size = 500 ) {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT comment_ID, comment_post_ID, comment_author, comment_author_email, comment_author_url, comment_content, comment_type, comment_date_gmt FROM {$wpdb->comments} WHERE comment_approved = '0' AND comment_ID > %d ORDER BY comment_ID ASC LIMIT %d", $cursor, $size ) ); // phpcs:ignore
		$spam    = array();
		$samples = array();
		foreach ( $rows as $r ) {
			$cursor = (int) $r->comment_ID;
			if ( self::spam_score( $r ) >= 2 ) {
				$spam[] = (int) $r->comment_ID;
				if ( count( $samples ) < 3 ) {
					$samples[] = array( 'author' => mb_substr( $r->comment_author, 0, 40 ), 'text' => mb_substr( wp_strip_all_tags( $r->comment_content ), 0, 90 ) );
				}
			}
		}
		if ( $apply && $spam ) {
			$ids = implode( ',', array_map( 'intval', $spam ) );
			$wpdb->query( "UPDATE {$wpdb->comments} SET comment_approved = 'spam' WHERE comment_approved = '0' AND comment_ID IN ($ids)" ); // phpcs:ignore -- integers only.
			clean_comment_cache( $spam );
			delete_transient( 'wc_count_comments' );
			wp_cache_delete( 'comments-0', 'counts' );
		}
		return array(
			'cursor'  => $cursor,
			'scanned' => count( $rows ),
			'spam'    => count( $spam ),
			'samples' => $samples,
			'done'    => count( $rows ) < $size,
		);
	}

	/** Permanently delete one batch of comments in the spam folder. */
	public static function empty_spam_batch( $size = 1000 ) {
		global $wpdb;
		$ids = array_map( 'intval', $wpdb->get_col( $wpdb->prepare( "SELECT comment_ID FROM {$wpdb->comments} WHERE comment_approved = 'spam' LIMIT %d", $size ) ) ); // phpcs:ignore
		if ( $ids ) {
			$in = implode( ',', $ids );
			$wpdb->query( "DELETE FROM {$wpdb->commentmeta} WHERE comment_id IN ($in)" ); // phpcs:ignore -- integers only.
			$wpdb->query( "DELETE FROM {$wpdb->comments} WHERE comment_ID IN ($in)" ); // phpcs:ignore
			clean_comment_cache( $ids );
			wp_cache_delete( 'comments-0', 'counts' );
		}
		return array( 'deleted' => count( $ids ), 'done' => count( $ids ) < $size );
	}
}
