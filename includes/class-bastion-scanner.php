<?php
/**
 * Resumable security scanner.
 *
 * Steps: core checksums → plugin checksums & WordPress.org status → file list → file checks
 * (integrity + malware signatures) → missing core files → known vulnerabilities → database
 * injections → configuration checks → finish.
 *
 * Work is done in time-boxed slices (AJAX while the admin watches, WP-Cron otherwise), so
 * scans never hit PHP time limits on shared hosting. Files that match the official
 * WordPress.org checksums are trusted and skipped, which keeps scans fast and false
 * positives rare.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_Scanner {

	const STATE    = 'bastion_scan_state';
	const LOCK     = 'bastion_scan_lock';
	const CRON     = 'bastion_scan_continue';
	const STEPS    = array( 'prepare', 'plugins', 'build', 'files', 'core_missing', 'vulns', 'database', 'config', 'finish' );
	const EXEC_EXT = '~\.(?:php\d?|phtml|phar|pht|phps|inc)$~i';
	const MAX_FILES = 400000;

	/** @var array|null */
	private static $core_sums;

	/** @var array */
	private static $plugin_sums = array();

	public static function init() {
		add_action( self::CRON, array( __CLASS__, 'cron_continue' ) );
		add_action( 'bastion_scheduled_scan', array( __CLASS__, 'scheduled' ) );
	}

	/* ============================================================ control */

	public static function state() {
		$s = get_option( self::STATE, array() );
		return is_array( $s ) ? $s : array();
	}

	private static function save( array $state ) {
		$state['updated'] = time();
		update_option( self::STATE, $state, false );
	}

	public static function is_running() {
		$s = self::state();
		return ! empty( $s['status'] ) && 'running' === $s['status'] && $s['updated'] > time() - 15 * MINUTE_IN_SECONDS;
	}

	public static function scan_dir() {
		return BASTION_WAF_DIR . '/scan';
	}

	public static function start( $trigger = 'manual' ) {
		if ( self::is_running() ) {
			return self::state();
		}
		Bastion_Firewall::storage()->ensure_dir( 'scan' );
		foreach ( (array) glob( self::scan_dir() . '/*.{txt,json}', GLOB_BRACE ) as $f ) {
			@unlink( $f );
		}
		$state = array(
			'id'          => time(),
			'status'      => 'running',
			'trigger'     => $trigger,
			'started'     => time(),
			'step'        => 'prepare',
			'cursor'      => 0,
			'files_total' => 0,
			'files_done'  => 0,
			'found'       => 0,
			'message'     => __( 'Starting scan…', 'bastion-security' ),
			'plugins'     => array(),
			'targets'     => array(),
			'log'         => array(),
		);
		self::save( $state );
		self::schedule_continue( 5 );
		return $state;
	}

	public static function stop() {
		$state = self::state();
		if ( $state ) {
			$state['status']  = 'stopped';
			$state['message'] = __( 'Scan stopped.', 'bastion-security' );
			self::save( $state );
		}
		wp_clear_scheduled_hook( self::CRON );
		delete_transient( self::LOCK );
	}

	public static function scheduled() {
		if ( 'off' !== Bastion_Settings::get( 'scan_schedule' ) ) {
			self::start( 'scheduled' );
		}
	}

	public static function cron_continue() {
		self::run_for( 20 );
	}

	private static function schedule_continue( $delay ) {
		if ( ! wp_next_scheduled( self::CRON ) ) {
			wp_schedule_single_event( time() + $delay, self::CRON );
		}
	}

	/**
	 * Do up to $seconds of work.
	 */
	public static function run_for( $seconds ) {
		if ( get_transient( self::LOCK ) ) {
			return self::state();
		}
		set_transient( self::LOCK, 1, $seconds + 60 );
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( $seconds + 60 );
		}
		$deadline = microtime( true ) + $seconds;
		$state    = self::state();

		try {
			while ( ! empty( $state['status'] ) && 'running' === $state['status'] && microtime( true ) < $deadline ) {
				$method = 'step_' . $state['step'];
				$done   = self::$method( $state, $deadline );
				if ( $done ) {
					$i               = array_search( $state['step'], self::STEPS, true );
					$state['cursor'] = 0;
					if ( false === $i || ! isset( self::STEPS[ $i + 1 ] ) ) {
						$state['status'] = 'complete';
					} else {
						$state['step'] = self::STEPS[ $i + 1 ];
					}
				}
				self::save( $state );
			}
		} catch ( Throwable $e ) {
			$state['status']  = 'failed';
			$state['message'] = 'Scan failed: ' . $e->getMessage();
			self::save( $state );
		}

		delete_transient( self::LOCK );
		if ( 'running' === $state['status'] ) {
			self::schedule_continue( 10 );
		}
		return $state;
	}

	private static function note( array &$state, $msg ) {
		$state['message'] = $msg;
		$state['log'][]   = array( time(), $msg );
		$state['log']     = array_slice( $state['log'], -40 );
	}

	/* ============================================================== steps */

	private static function step_prepare( array &$state, $deadline ) {
		self::note( $state, __( 'Fetching official WordPress core checksums…', 'bastion-security' ) );
		$sums = self::fetch_core_sums();
		if ( ! $sums ) {
			self::note( $state, __( 'Could not download core checksums from WordPress.org; core integrity is skipped this time.', 'bastion-security' ) );
		}
		$state['core_ok'] = (bool) $sums;
		return true;
	}

	private static function step_plugins( array &$state, $deadline ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( empty( $state['plugin_list'] ) ) {
			$list = array();
			foreach ( get_plugins() as $file => $data ) {
				$slug = dirname( $file );
				if ( '.' === $slug ) {
					continue; // Single-file plugins (no checksum source).
				}
				$list[] = array(
					'slug'    => $slug,
					'version' => $data['Version'],
					'name'    => $data['Name'],
					'file'    => $file,
					'org'     => self::from_org( $data ),
				);
			}
			$state['plugin_list'] = $list;
			self::note( $state, sprintf( __( 'Checking %d plugins against WordPress.org…', 'bastion-security' ), count( $list ) ) );
		}
		$list = $state['plugin_list'];
		while ( $state['cursor'] < count( $list ) ) {
			if ( microtime( true ) > $deadline ) {
				return false;
			}
			$p = $list[ $state['cursor'] ];
			$state['cursor']++;
			$state['message'] = sprintf( __( 'Checking plugin %s…', 'bastion-security' ), $p['name'] );

			$org = false;
			if ( isset( $p['org'] ) && ! $p['org'] ) {
				// Declares it is updated from somewhere else (Update URI): a WordPress.org plugin
				// with the same folder name is a different plugin, so its data says nothing here.
				$state['custom_plugins'][] = $p['slug'];
				continue;
			}
			if ( Bastion_Settings::get( 'scan_plugin_integrity' ) ) {
				$sums = self::fetch_plugin_sums( $p['slug'], $p['version'] );
				if ( $sums ) {
					$org = true;
					file_put_contents( self::scan_dir() . '/plugin-' . md5( $p['slug'] ) . '.json', wp_json_encode( $sums ) );
					$state['plugins'][ $p['slug'] ] = $p['version'];
				}
			}

			if ( Bastion_Settings::get( 'scan_abandoned' ) ) {
				$info = self::plugin_info( $p['slug'] );
				if ( is_array( $info ) && isset( $info['error'] ) && 'closed' === $info['error'] ) {
					self::issue(
						$state,
						'plugin_closed',
						Bastion_Events::HIGH,
						'plugin:' . $p['slug'],
						sprintf( __( 'Plugin "%s" was closed on WordPress.org', 'bastion-security' ), $p['name'] ),
						array(
							'reason' => isset( $info['reason_text'] ) ? $info['reason_text'] : ( isset( $info['reason'] ) ? $info['reason'] : '' ),
							'date'   => isset( $info['closed_date'] ) ? $info['closed_date'] : '',
							'help'   => __( 'Closed plugins no longer receive updates, often because of an unfixed security problem. Replace it with a maintained alternative.', 'bastion-security' ),
						)
					);
				} elseif ( is_array( $info ) && ! empty( $info['last_updated'] ) ) {
					$updated = strtotime( $info['last_updated'] );
					if ( $updated && $updated < time() - 2 * YEAR_IN_SECONDS ) {
						self::issue(
							$state,
							'plugin_abandoned',
							Bastion_Events::MEDIUM,
							'plugin:' . $p['slug'],
							sprintf( __( 'Plugin "%1$s" has not been updated in %2$s', 'bastion-security' ), $p['name'], human_time_diff( $updated ) ),
							array( 'help' => __( 'Abandoned plugins do not get security fixes. Consider replacing it.', 'bastion-security' ) )
						);
					}
				}
			}
			if ( ! $org ) {
				$state['custom_plugins'][] = $p['slug'];
			}
		}
		return true;
	}

	/**
	 * Other security tools' rule and signature files. They contain malware patterns on purpose
	 * (to detect them), so scanning them only produces false alarms.
	 */
	const SIGNATURE_STORES = array( 'wp-content/wflogs/', 'wp-content/plugins/wordfence/', 'wp-content/uploads/sucuri/', 'wp-content/plugins/sucuri-scanner/', 'wp-content/plugins/ninjafirewall/', 'wp-content/nfwlog/', 'wp-content/plugins/malcare-security/', 'wp-content/mc_data/', 'wp-content/plugins/all-in-one-wp-security-and-firewall/', 'wp-content/aios/', 'wp-content/plugins/wp-cerber/', 'wp-content/plugins/better-wp-security/', 'wp-content/uploads/ithemes-security/', 'wp-content/plugins/defender-security/' );

	/** True unless the plugin declares updates from somewhere other than WordPress.org (Update URI). */
	public static function from_org( array $data ) {
		$uri = isset( $data['UpdateURI'] ) ? trim( (string) $data['UpdateURI'] ) : '';
		if ( '' === $uri ) {
			return true;
		}
		$host = wp_parse_url( false === strpos( $uri, '://' ) ? 'https://' . $uri : $uri, PHP_URL_HOST );
		return in_array( strtolower( (string) $host ), array( 'w.org', 'wordpress.org' ), true );
	}

	private static function step_build( array &$state, $deadline ) {
		self::note( $state, __( 'Listing files…', 'bastion-security' ) );
		$queue = self::scan_dir() . '/queue.txt';
		$fh    = fopen( $queue, 'w' );
		if ( ! $fh ) {
			throw new RuntimeException( 'Cannot write the scan queue in ' . self::scan_dir() );
		}
		$roots = array( wp_normalize_path( untrailingslashit( ABSPATH ) ) );
		$wpc   = wp_normalize_path( WP_CONTENT_DIR );
		if ( 0 !== strpos( $wpc, $roots[0] . '/' ) ) {
			$roots[] = $wpc;
		}
		$exclude = array_merge(
			(array) Bastion_Settings::get( 'scan_exclude' ),
			array( wp_normalize_path( BASTION_WAF_DIR ) . '/' ),
			self::SIGNATURE_STORES
		);
		$count = 0;
		foreach ( $roots as $root ) {
			try {
				$it = new RecursiveIteratorIterator(
					new RecursiveCallbackFilterIterator(
						new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO ),
						function ( $f ) use ( $exclude ) {
							$path = wp_normalize_path( $f->getPathname() ) . ( $f->isDir() ? '/' : '' );
							foreach ( $exclude as $ex ) {
								if ( '' !== $ex && false !== strpos( $path, $ex ) ) {
									return false;
								}
							}
							if ( $f->isLink() ) {
								return false;
							}
							return $f->isDir() ? $f->isReadable() : true;
						}
					),
					RecursiveIteratorIterator::LEAVES_ONLY,
					RecursiveIteratorIterator::CATCH_GET_CHILD
				);
				foreach ( $it as $file ) {
					if ( ! $file->isFile() || ! self::wanted( $file->getFilename() ) ) {
						continue;
					}
					fwrite( $fh, wp_normalize_path( $file->getPathname() ) . "\n" );
					if ( ++$count >= self::MAX_FILES ) {
						break 2;
					}
				}
			} catch ( Exception $e ) {
				self::note( $state, 'Could not read ' . $root . ': ' . $e->getMessage() );
			}
		}
		fclose( $fh );
		$state['files_total'] = $count;
		self::note( $state, sprintf( __( 'Scanning %s files…', 'bastion-security' ), number_format_i18n( $count ) ) );
		return true;
	}

	private static function wanted( $name ) {
		$lower = strtolower( $name );
		if ( in_array( $lower, array( '.htaccess', '.user.ini', 'php.ini' ), true ) ) {
			return true;
		}
		return (bool) preg_match( '~\.(?:php\d?|phtml|phar|pht|phps|inc|js|html?|svg|ico|suspected)$~', $lower );
	}

	private static function step_files( array &$state, $deadline ) {
		$fh = fopen( self::scan_dir() . '/queue.txt', 'r' );
		if ( ! $fh ) {
			return true;
		}
		fseek( $fh, (int) $state['cursor'] );
		$n = 0;
		while ( microtime( true ) < $deadline ) {
			$line = fgets( $fh );
			if ( false === $line ) {
				fclose( $fh );
				return true;
			}
			$abs = rtrim( $line, "\n" );
			if ( '' !== $abs && is_file( $abs ) ) {
				self::scan_file( $state, $abs );
			}
			$state['files_done']++;
			if ( 0 === ++$n % 50 ) {
				$state['cursor'] = ftell( $fh );
			}
		}
		$state['cursor']  = ftell( $fh );
		$state['message'] = sprintf( __( 'Scanned %1$s of %2$s files…', 'bastion-security' ), number_format_i18n( $state['files_done'] ), number_format_i18n( $state['files_total'] ) );
		fclose( $fh );
		return false;
	}

	private static function step_core_missing( array &$state, $deadline ) {
		$skip = array( 'wp-config-sample.php', 'readme.html', 'license.txt', 'wp-content/index.php' );
		foreach ( self::core_sums() as $rel => $md5 ) {
			if ( in_array( $rel, $skip, true ) ) {
				continue;
			}
			if ( ! file_exists( ABSPATH . $rel ) ) {
				self::issue( $state, 'core_missing', Bastion_Events::MEDIUM, $rel, __( 'WordPress core file is missing', 'bastion-security' ), array( 'repairable' => true ) );
			}
		}
		return true;
	}

	private static function step_vulns( array &$state, $deadline ) {
		if ( ! Bastion_Settings::get( 'scan_vulnerabilities' ) ) {
			return true;
		}
		if ( empty( $state['targets'] ) ) {
			global $wp_version;
			$targets = array( array( 'core', 'wordpress', $wp_version, 'WordPress' ) );
			foreach ( (array) $state['plugin_list'] as $p ) {
				if ( isset( $p['org'] ) && ! $p['org'] ) {
					continue; // Not the WordPress.org plugin of that name: its advisories don't apply.
				}
				$targets[] = array( 'plugin', $p['slug'], $p['version'], $p['name'] );
			}
			foreach ( wp_get_themes() as $slug => $theme ) {
				$targets[] = array( 'theme', $slug, $theme->get( 'Version' ), $theme->get( 'Name' ) );
			}
			$state['targets'] = $targets;
			self::note( $state, __( 'Checking known vulnerabilities…', 'bastion-security' ) );
		}
		while ( $state['cursor'] < count( $state['targets'] ) ) {
			if ( microtime( true ) > $deadline ) {
				return false;
			}
			list( $kind, $slug, $version, $name ) = $state['targets'][ $state['cursor'] ];
			$state['cursor']++;
			$state['message'] = sprintf( __( 'Checking vulnerabilities: %s', 'bastion-security' ), $name );
			foreach ( self::vulnerabilities( $kind, $slug, $version ) as $v ) {
				$help = $v['unfixed']
					? __( 'No fixed version exists yet. Deactivate and replace it, or keep the firewall enabled until a fix ships.', 'bastion-security' )
					: ( $v['fixed_in'] ? sprintf( __( 'Update to version %s or later.', 'bastion-security' ), $v['fixed_in'] ) : __( 'Update to the latest version.', 'bastion-security' ) );
				self::issue(
					$state,
					'vuln',
					$v['severity'],
					$kind . ':' . $slug,
					sprintf( '%s %s: %s', $name, $version, $v['name'] ),
					array(
						'kind'    => $kind,
						'slug'    => $slug,
						'links'   => $v['links'],
						'help'    => $help,
						'sig'     => $v['id'],
						'unfixed' => $v['unfixed'],
					)
				);
			}
		}
		return true;
	}

	private static function step_database( array &$state, $deadline ) {
		if ( ! Bastion_Settings::get( 'scan_database' ) ) {
			return true;
		}
		global $wpdb;
		self::note( $state, __( 'Scanning posts and options for injected code…', 'bastion-security' ) );
		$host  = wp_parse_url( home_url(), PHP_URL_HOST );
		$posts = $wpdb->get_results( "SELECT ID, post_title, post_type, post_content FROM {$wpdb->posts} WHERE post_status IN ('publish','future','draft','private','pending') AND post_type NOT IN ('revision','customize_changeset','oembed_cache') AND (post_content LIKE '%<script%' OR post_content LIKE '%<iframe%' OR post_content LIKE '%fromCharCode%' OR post_content LIKE '%eval(%') LIMIT 3000" ); // phpcs:ignore
		foreach ( (array) $posts as $p ) {
			$hits = self::db_hits( $p->post_content, $host );
			foreach ( $hits as $h ) {
				self::issue(
					$state,
					'db_injection',
					$h['sev'],
					'db:post:' . $p->ID,
					sprintf( __( 'Suspicious code in %1$s "%2$s": %3$s', 'bastion-security' ), $p->post_type, wp_strip_all_tags( $p->post_title ), $h['desc'] ),
					array( 'sig' => $h['id'], 'snippet' => $h['snippet'], 'post_id' => (int) $p->ID )
				);
			}
		}
		$options = $wpdb->get_results( "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name NOT LIKE '\_transient%' AND option_name NOT LIKE '\_site\_transient%' AND (option_value LIKE '%eval(%' OR option_value LIKE '%base64_decode(%' OR option_value LIKE '%fromCharCode%' OR option_value LIKE '%<script%') LIMIT 500" ); // phpcs:ignore
		foreach ( (array) $options as $o ) {
			foreach ( self::db_hits( $o->option_value, $host, true ) as $h ) {
				self::issue(
					$state,
					'db_injection',
					$h['sev'],
					'db:option:' . $o->option_name,
					sprintf( __( 'Suspicious code in option "%1$s": %2$s', 'bastion-security' ), $o->option_name, $h['desc'] ),
					array( 'sig' => $h['id'], 'snippet' => $h['snippet'] )
				);
			}
		}
		return true;
	}

	private static function db_hits( $content, $host, $with_php = false ) {
		$hits = Bastion_Signatures::scan( (string) $content, 'js' );
		if ( $with_php ) {
			$hits = array_merge( $hits, Bastion_Signatures::scan( (string) $content, 'php' ) );
		}
		if ( preg_match_all( '~<script[^>]+src\s*=\s*[\'"]?(https?:)?//([^/\'"\s>]+)~i', (string) $content, $m, PREG_SET_ORDER ) ) {
			foreach ( $m as $match ) {
				$domain = strtolower( $match[2] );
				if ( $domain === $host ) {
					continue;
				}
				if ( preg_match( '~^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$|\.(?:tk|top|xyz|ru|cn|ga|ml|cf|gq|pw|cc|su|icu|buzz|monster|rest|cyou)$~', $domain ) ) {
					$hits[] = array( 'id' => 'db-ext-script', 'sev' => Bastion_Events::HIGH, 'desc' => 'Script loaded from suspicious domain ' . $domain, 'line' => 0, 'snippet' => substr( $match[0], 0, 160 ) );
				}
			}
		}
		return $hits;
	}

	private static function step_config( array &$state, $deadline ) {
		self::note( $state, __( 'Checking configuration…', 'bastion-security' ) );
		foreach ( Bastion_Hardening::checks() as $c ) {
			if ( 'pass' === $c['status'] || 'scan_recent' === $c['id'] ) {
				continue;
			}
			$sev = 'warn' === $c['status'] ? Bastion_Events::LOW : ( $c['weight'] >= 10 ? Bastion_Events::HIGH : ( $c['weight'] >= 5 ? Bastion_Events::MEDIUM : Bastion_Events::LOW ) );
			self::issue( $state, 'config', $sev, 'config:' . $c['id'], $c['title'] . ' — ' . __( 'not met', 'bastion-security' ), array( 'help' => $c['detail'], 'fix' => $c['fix'] ) );
		}
		return true;
	}

	private static function step_finish( array &$state, $deadline ) {
		global $wpdb;
		$table = Bastion_DB::issues_table();
		// Anything not seen in this scan has been fixed or removed.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE scan_id <> %d", $state['id'] ) ); // phpcs:ignore

		$new = $wpdb->get_results( $wpdb->prepare( "SELECT severity, title, file FROM {$table} WHERE status = 'open' AND first_seen >= %d AND severity >= %d ORDER BY severity DESC LIMIT 20", $state['started'], Bastion_Events::HIGH ) ); // phpcs:ignore
		$open = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE status = 'open'" ); // phpcs:ignore

		update_option( 'bastion_last_scan_completed', time(), false );
		@unlink( self::scan_dir() . '/queue.txt' );
		foreach ( (array) glob( self::scan_dir() . '/plugin-*.json' ) as $f ) {
			@unlink( $f );
		}
		$duration = time() - $state['started'];
		self::note( $state, sprintf( __( 'Scan complete: %1$s files in %2$s, %3$d open issues.', 'bastion-security' ), number_format_i18n( $state['files_done'] ), human_time_diff( 0, max( 1, $duration ) ), $open ) );
		unset( $state['plugin_list'], $state['targets'] );
		Bastion_Events::log( 'scan_complete', $state['message'], array( 'severity' => $new ? Bastion_Events::HIGH : Bastion_Events::INFO, 'data' => array( 'files' => $state['files_done'], 'open' => $open, 'new_high' => count( $new ) ) ) );

		if ( $new && Bastion_Settings::get( 'alert_scan' ) ) {
			$lines = array();
			foreach ( $new as $i ) {
				$lines[] = '• [' . self::severity_label( $i->severity ) . '] ' . $i->title . ( $i->file && false === strpos( $i->file, ':' ) ? "\n  " . $i->file : '' );
			}
			Bastion_Events::alert(
				'scan_' . $state['id'],
				sprintf( _n( 'Scan found %d new serious issue', 'Scan found %d new serious issues', count( $new ), 'bastion-security' ), count( $new ) ),
				implode( "\n", $lines ) . "\n\n" . __( 'Review them in Bastion → Scanner:', 'bastion-security' ) . ' ' . admin_url( 'admin.php?page=bastion-scanner' )
			);
		}
		return true;
	}

	/* ===================================================== per-file checks */

	public static function rel( $abs ) {
		$abs  = wp_normalize_path( $abs );
		$wpc  = wp_normalize_path( WP_CONTENT_DIR );
		$root = wp_normalize_path( ABSPATH );
		if ( 0 === strpos( $abs, $wpc . '/' ) ) {
			return 'wp-content/' . substr( $abs, strlen( $wpc ) + 1 );
		}
		if ( 0 === strpos( $abs, $root ) ) {
			return substr( $abs, strlen( $root ) );
		}
		return $abs;
	}

	public static function abs_path( $rel ) {
		if ( 0 === strpos( $rel, 'wp-content/' ) ) {
			return wp_normalize_path( WP_CONTENT_DIR ) . '/' . substr( $rel, 11 );
		}
		if ( '/' === substr( $rel, 0, 1 ) || preg_match( '~^[a-z]:/~i', $rel ) ) {
			return $rel;
		}
		return wp_normalize_path( ABSPATH ) . $rel;
	}

	private static function uploads_rel() {
		static $rel = null;
		if ( null === $rel ) {
			$u   = wp_upload_dir( null, false );
			$rel = self::rel( $u['basedir'] ) . '/';
		}
		return $rel;
	}

	private static function scan_file( array &$state, $abs ) {
		$rel  = self::rel( $abs );
		$base = strtolower( basename( $abs ) );
		$ext  = strtolower( pathinfo( $abs, PATHINFO_EXTENSION ) );
		$size = @filesize( $abs );
		if ( false === $size ) {
			return;
		}
		$is_php = (bool) preg_match( self::EXEC_EXT, $base );

		// 1. WordPress core integrity.
		$core = self::core_sums();
		if ( isset( $core[ $rel ] ) ) {
			$md5 = md5_file( $abs );
			if ( $md5 === $core[ $rel ] ) {
				return; // Pristine official file.
			}
			self::issue( $state, 'core_modified', Bastion_Events::HIGH, $rel, __( 'WordPress core file was modified', 'bastion-security' ), array( 'repairable' => true, 'expected' => $core[ $rel ], 'actual' => $md5 ), $md5 );
		} elseif ( $core && ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) ) {
			self::issue( $state, 'core_unknown', $is_php ? Bastion_Events::HIGH : Bastion_Events::MEDIUM, $rel, __( 'Unknown file inside a WordPress core folder', 'bastion-security' ), array( 'help' => __( 'WordPress never puts this file here. Malware often hides in core folders.', 'bastion-security' ) ), md5_file( $abs ) );
		}

		// 2. Plugin integrity (WordPress.org plugins).
		if ( preg_match( '~^wp-content/plugins/([^/]+)/(.+)$~', $rel, $m ) && isset( $state['plugins'][ $m[1] ] ) ) {
			$sums = self::plugin_sums( $m[1] );
			if ( isset( $sums[ $m[2] ] ) ) {
				$md5 = md5_file( $abs );
				if ( in_array( $md5, (array) $sums[ $m[2] ], true ) ) {
					return; // Matches the official release.
				}
				self::issue( $state, 'plugin_modified', Bastion_Events::HIGH, $rel, sprintf( __( 'File differs from the official %1$s %2$s release', 'bastion-security' ), $m[1], $state['plugins'][ $m[1] ] ), array( 'repairable' => true, 'slug' => $m[1], 'version' => $state['plugins'][ $m[1] ] ), $md5 );
			} elseif ( $is_php ) {
				self::issue( $state, 'plugin_unknown', Bastion_Events::MEDIUM, $rel, sprintf( __( 'PHP file is not part of the official %1$s %2$s release', 'bastion-security' ), $m[1], $state['plugins'][ $m[1] ] ), array( 'help' => __( 'Could be a leftover from an older version, a cache file, or an injected backdoor. Review the code.', 'bastion-security' ) ), md5_file( $abs ) );
			}
		}

		// 3. Executable files in uploads.
		$in_uploads = 0 === strpos( $rel, self::uploads_rel() );
		if ( $in_uploads && $is_php && 'index.php' !== $base ) {
			self::issue( $state, 'php_in_uploads', Bastion_Events::HIGH, $rel, __( 'PHP file in the uploads folder', 'bastion-security' ), array( 'help' => __( 'The uploads folder should only contain media. PHP files here are a classic backdoor location.', 'bastion-security' ) ), md5_file( $abs ) );
		}

		// 4. Malware signatures.
		if ( ! Bastion_Settings::get( 'scan_signatures' ) ) {
			return;
		}
		$max = (int) Bastion_Settings::get( 'scan_max_file_mb' ) * 1048576;
		if ( $size > $max || 0 === $size ) {
			return;
		}
		$content = (string) @file_get_contents( $abs );
		$hits    = array();
		if ( in_array( $base, array( '.htaccess', '.user.ini', 'php.ini' ), true ) ) {
			$hits = Bastion_Signatures::scan( $content, 'htaccess' );
		} elseif ( $is_php || 'suspected' === $ext ) {
			$hits = array_merge( Bastion_Signatures::scan( $content, 'php' ), Bastion_Signatures::scan( $content, 'js' ) );
		} elseif ( in_array( $ext, array( 'js', 'html', 'htm', 'svg' ), true ) ) {
			$hits = Bastion_Signatures::scan( $content, 'js' );
		}
		if ( in_array( $ext, array( 'ico', 'svg', 'js', 'html', 'htm' ), true ) && preg_match( '~<\?php\b~i', $content ) ) {
			$hits[] = array( 'id' => 'php-in-media', 'sev' => Bastion_Events::HIGH, 'desc' => 'PHP code hidden in a non-PHP file', 'line' => 0, 'snippet' => '' );
		}
		foreach ( $hits as $h ) {
			self::issue(
				$state,
				'malware',
				$h['sev'],
				$rel,
				$h['desc'],
				array( 'sig' => $h['id'], 'line' => $h['line'], 'snippet' => $h['snippet'] ),
				md5( $content )
			);
		}
	}

	/* ========================================================= checksums */

	private static function fetch_core_sums() {
		global $wp_version;
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$sums = get_core_checksums( $wp_version, get_locale() );
		if ( ! $sums && 'en_US' !== get_locale() ) {
			$sums = get_core_checksums( $wp_version, 'en_US' );
		}
		if ( ! is_array( $sums ) ) {
			delete_option( 'bastion_core_sums' );
			return array();
		}
		$clean = array();
		foreach ( $sums as $file => $md5 ) {
			if ( 0 !== strpos( $file, 'wp-content/' ) ) {
				$clean[ $file ] = $md5;
			}
		}
		update_option( 'bastion_core_sums', array( 'version' => $wp_version, 'sums' => $clean ), false );
		self::$core_sums = $clean;
		return $clean;
	}

	public static function core_sums() {
		if ( null === self::$core_sums ) {
			global $wp_version;
			$o               = get_option( 'bastion_core_sums' );
			self::$core_sums = is_array( $o ) && isset( $o['version'] ) && $o['version'] === $wp_version ? $o['sums'] : array();
		}
		return self::$core_sums;
	}

	private static function fetch_plugin_sums( $slug, $version ) {
		$url = sprintf( 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json', rawurlencode( $slug ), rawurlencode( $version ) );
		$res = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $res ) || 200 !== wp_remote_retrieve_response_code( $res ) ) {
			return array();
		}
		$data = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return array();
		}
		$out = array();
		foreach ( $data['files'] as $file => $h ) {
			if ( isset( $h['md5'] ) ) {
				$out[ $file ] = (array) $h['md5'];
			}
		}
		return $out;
	}

	private static function plugin_sums( $slug ) {
		if ( ! isset( self::$plugin_sums[ $slug ] ) ) {
			$file                       = self::scan_dir() . '/plugin-' . md5( $slug ) . '.json';
			$data                       = is_file( $file ) ? json_decode( (string) file_get_contents( $file ), true ) : array();
			self::$plugin_sums          = array( $slug => is_array( $data ) ? $data : array() ); // Keep one plugin in memory.
		}
		return self::$plugin_sums[ $slug ];
	}

	private static function plugin_info( $slug ) {
		$url = add_query_arg(
			array(
				'action'                    => 'plugin_information',
				'request[slug]'             => $slug,
				'request[fields][sections]' => 0,
				'request[fields][versions]' => 0,
				'request[fields][reviews]'  => 0,
			),
			'https://api.wordpress.org/plugins/info/1.2/'
		);
		$res = wp_remote_get( $url, array( 'timeout' => 10 ) );
		if ( is_wp_error( $res ) ) {
			return null;
		}
		$data = json_decode( wp_remote_retrieve_body( $res ), true );
		return is_array( $data ) ? $data : null;
	}

	/* ===================================================== vulnerabilities */

	/**
	 * Known vulnerabilities affecting an installed version (WPVulnerability.net, free, no key).
	 *
	 * @return array[] id, name, severity, fixed_in, unfixed, links
	 */
	public static function vulnerabilities( $kind, $slug, $version ) {
		$cache_key = 'bastion_vuln_' . md5( $kind . $slug . $version );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$path = 'core' === $kind ? 'core/' . rawurlencode( $version ) : $kind . '/' . rawurlencode( $slug );
		$res  = wp_remote_get( 'https://www.wpvulnerability.net/' . $path . '/', array( 'timeout' => 10 ) );
		if ( is_wp_error( $res ) || 200 !== wp_remote_retrieve_response_code( $res ) ) {
			return array();
		}
		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		$out  = array();
		$list = isset( $body['data']['vulnerability'] ) && is_array( $body['data']['vulnerability'] ) ? $body['data']['vulnerability'] : array();
		foreach ( $list as $v ) {
			$op = isset( $v['operator'] ) ? $v['operator'] : array();
			if ( 'core' !== $kind && ! self::version_affected( $version, $op ) ) {
				continue;
			}
			$links = array();
			foreach ( array_slice( isset( $v['source'] ) ? (array) $v['source'] : array(), 0, 3 ) as $src ) {
				if ( ! empty( $src['link'] ) ) {
					$links[] = array( 'name' => isset( $src['name'] ) ? wp_strip_all_tags( html_entity_decode( $src['name'] ) ) : $src['link'], 'url' => esc_url_raw( $src['link'] ) );
				}
			}
			$sev_map = array( 'c' => 4, 'h' => 3, 'm' => 2, 'l' => 1, 'n' => 1 );
			$sev     = isset( $v['impact']['cvss']['severity'] ) && isset( $sev_map[ $v['impact']['cvss']['severity'] ] ) ? $sev_map[ $v['impact']['cvss']['severity'] ] : 3;
			$fixed   = ! empty( $op['max_version'] ) && in_array( isset( $op['max_operator'] ) ? $op['max_operator'] : '', array( 'lt' ), true ) ? $op['max_version'] : '';
			$out[]   = array(
				'id'       => isset( $v['uuid'] ) ? substr( $v['uuid'], 0, 32 ) : md5( wp_json_encode( $v ) ),
				'name'     => isset( $v['name'] ) ? wp_strip_all_tags( html_entity_decode( $v['name'] ) ) : 'Vulnerability',
				'severity' => $sev,
				'fixed_in' => $fixed,
				'unfixed'  => ! empty( $op['unfixed'] ) && '0' !== (string) $op['unfixed'],
				'links'    => $links,
			);
		}
		set_transient( $cache_key, $out, 12 * HOUR_IN_SECONDS );
		return $out;
	}

	public static function version_affected( $version, array $op ) {
		$map = array( 'lt' => '<', 'le' => '<=', 'gt' => '>', 'ge' => '>=', 'eq' => '==' );
		if ( ! empty( $op['min_version'] ) && ! empty( $op['min_operator'] ) && isset( $map[ $op['min_operator'] ] ) ) {
			if ( ! version_compare( $version, $op['min_version'], $map[ $op['min_operator'] ] ) ) {
				return false;
			}
		}
		if ( ! empty( $op['max_version'] ) && ! empty( $op['max_operator'] ) && isset( $map[ $op['max_operator'] ] ) ) {
			if ( ! version_compare( $version, $op['max_version'], $map[ $op['max_operator'] ] ) ) {
				return false;
			}
		}
		return ! empty( $op['min_version'] ) || ! empty( $op['max_version'] ) || ! empty( $op['unfixed'] );
	}

	/* ============================================================== issues */

	private static function issue( array &$state, $type, $severity, $file, $title, array $details = array(), $hash = '' ) {
		global $wpdb;
		$table = Bastion_DB::issues_table();
		$key   = md5( $type . '|' . $file . '|' . ( isset( $details['sig'] ) ? $details['sig'] : '' ) );
		$now   = time();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT id, status, file_hash FROM {$table} WHERE issue_key = %s", $key ) ); // phpcs:ignore
		$data  = array(
			'type'      => $type,
			'severity'  => (int) $severity,
			'file'      => substr( $file, 0, 1024 ),
			'title'     => substr( wp_strip_all_tags( $title ), 0, 255 ),
			'details'   => wp_json_encode( $details ),
			'last_seen' => $now,
			'scan_id'   => (int) $state['id'],
		);
		if ( $row ) {
			// Ignored issues stay ignored unless the file changed since.
			if ( 'ignored' === $row->status && $hash && $row->file_hash !== $hash ) {
				$data['status'] = 'open';
			}
			// Found again after being fixed (e.g. a backdoor re-uploaded): it is a live problem.
			if ( 'resolved' === $row->status ) {
				$data['status']     = 'open';
				$data['first_seen'] = $now;
				$state['found']++;
			}
			$data['file_hash'] = $hash ? $hash : $row->file_hash;
			$wpdb->update( $table, $data, array( 'id' => $row->id ) ); // phpcs:ignore
		} else {
			$data['issue_key']  = $key;
			$data['status']     = 'open';
			$data['file_hash']  = $hash;
			$data['first_seen'] = $now;
			$wpdb->insert( $table, $data ); // phpcs:ignore
			$state['found']++;
		}
	}

	public static function get_issue( $id ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . Bastion_DB::issues_table() . ' WHERE id = %d', $id ) ); // phpcs:ignore
		if ( $row ) {
			$row->details = json_decode( (string) $row->details, true );
			if ( ! is_array( $row->details ) ) {
				$row->details = array();
			}
		}
		return $row;
	}

	public static function issues( $status = 'open' ) {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM ' . Bastion_DB::issues_table() . ' WHERE status = %s ORDER BY severity DESC, type, file LIMIT 2000', $status ) ); // phpcs:ignore
		foreach ( $rows as $r ) {
			$r->details = json_decode( (string) $r->details, true );
			if ( ! is_array( $r->details ) ) {
				$r->details = array();
			}
		}
		return $rows;
	}

	public static function issue_counts() {
		global $wpdb;
		$out  = array( 0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 'ignored' => 0 );
		$rows = $wpdb->get_results( 'SELECT status, severity, COUNT(*) AS n FROM ' . Bastion_DB::issues_table() . " WHERE type <> 'config' GROUP BY status, severity" ); // phpcs:ignore
		foreach ( (array) $rows as $r ) {
			if ( 'open' === $r->status ) {
				$out[ (int) $r->severity ] += (int) $r->n;
			} elseif ( 'ignored' === $r->status ) {
				$out['ignored'] += (int) $r->n;
			}
		}
		return $out;
	}

	/** Close every open finding about the same file (one file can match several checks). */
	private static function resolve_file( $issue ) {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . Bastion_DB::issues_table() . " SET status = 'resolved' WHERE file = %s AND status <> 'resolved'", $issue->file ) ); // phpcs:ignore
	}

	public static function set_status( $id, $status ) {
		global $wpdb;
		return false !== $wpdb->update( Bastion_DB::issues_table(), array( 'status' => $status ), array( 'id' => (int) $id ) ); // phpcs:ignore
	}

	public static function severity_label( $sev ) {
		$labels = array(
			0 => __( 'Info', 'bastion-security' ),
			1 => __( 'Low', 'bastion-security' ),
			2 => __( 'Medium', 'bastion-security' ),
			3 => __( 'High', 'bastion-security' ),
			4 => __( 'Critical', 'bastion-security' ),
		);
		return isset( $labels[ (int) $sev ] ) ? $labels[ (int) $sev ] : '';
	}

	/* ============================================================= actions */

	/**
	 * Resolve an issue's file to a safe absolute path, or WP_Error.
	 */
	private static function issue_file( $issue ) {
		if ( ! $issue || '' === $issue->file || false !== strpos( $issue->file, ':' ) && ! preg_match( '~^[a-z]:/~i', $issue->file ) ) {
			return new WP_Error( 'bastion_no_file', __( 'This issue is not about a file.', 'bastion-security' ) );
		}
		$abs  = self::abs_path( $issue->file );
		$real = realpath( $abs );
		$path = $real ? wp_normalize_path( $real ) : wp_normalize_path( $abs );
		$ok   = false;
		foreach ( array( ABSPATH, WP_CONTENT_DIR ) as $root ) {
			$root = trailingslashit( wp_normalize_path( realpath( $root ) ? realpath( $root ) : $root ) );
			if ( 0 === strpos( $path, $root ) ) {
				$ok = true;
			}
		}
		if ( ! $ok || false !== strpos( $issue->file, '..' ) ) {
			return new WP_Error( 'bastion_bad_path', __( 'File is outside the WordPress folders.', 'bastion-security' ) );
		}
		return $path;
	}

	public static function view_file( $id ) {
		$issue = self::get_issue( $id );
		$path  = self::issue_file( $issue );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		if ( ! is_file( $path ) ) {
			return new WP_Error( 'bastion_missing', __( 'The file no longer exists.', 'bastion-security' ) );
		}
		$size = filesize( $path );
		return array(
			'file'      => $issue->file,
			'size'      => $size,
			'modified'  => wp_date( 'Y-m-d H:i:s', filemtime( $path ) ),
			'content'   => wp_check_invalid_utf8( (string) file_get_contents( $path, false, null, 0, 300000 ), true ),
			'truncated' => $size > 300000,
			'line'      => isset( $issue->details['line'] ) ? (int) $issue->details['line'] : 0,
		);
	}

	private static function protected_file( $path ) {
		$base = basename( $path );
		return in_array( $base, array( 'wp-config.php', 'wp-settings.php', 'wp-load.php', 'wp-blog-header.php', 'index.php' ), true ) && dirname( wp_normalize_path( $path ) ) . '/' === wp_normalize_path( ABSPATH )
			|| 0 === strpos( wp_normalize_path( $path ), wp_normalize_path( BASTION_DIR ) );
	}

	/** Move a file to the quarantine (restorable) instead of deleting it. */
	public static function quarantine( $id ) {
		$issue = self::get_issue( $id );
		$path  = self::issue_file( $issue );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		if ( ! is_file( $path ) ) {
			self::resolve_file( $issue );
			return true;
		}
		if ( self::protected_file( $path ) ) {
			return new WP_Error( 'bastion_protected', __( 'This file is essential to WordPress. Use "Restore original" instead of quarantine.', 'bastion-security' ) );
		}
		$res = self::move_to_quarantine( $path, $issue->file, $issue->title );
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		self::resolve_file( $issue );
		Bastion_Events::log( 'file_quarantined', 'Quarantined ' . $issue->file . ' (' . $issue->title . ')', array( 'severity' => Bastion_Events::MEDIUM ) );
		return true;
	}

	private static function move_to_quarantine( $path, $rel, $reason ) {
		$storage = Bastion_Firewall::storage();
		$storage->ensure_dir( 'quarantine' );
		$name = gmdate( 'Ymd-His' ) . '-' . substr( md5( $rel . microtime() ), 0, 8 ) . '.q';
		$dest = $storage->path( 'quarantine/' . $name );
		if ( ! @rename( $path, $dest ) ) {
			if ( ! @copy( $path, $dest ) || ! @unlink( $path ) ) {
				return new WP_Error( 'bastion_move_failed', __( 'Could not move the file. Check file permissions.', 'bastion-security' ) );
			}
		}
		@chmod( $dest, 0600 );
		$index          = $storage->read_php_array( 'quarantine/manifest.php' );
		$index[ $name ] = array(
			'file'   => $rel,
			'reason' => $reason,
			'time'   => time(),
			'size'   => filesize( $dest ),
			'user'   => wp_get_current_user()->user_login,
		);
		$storage->write_php_array( 'quarantine/manifest.php', $index );
		return $name;
	}

	public static function quarantine_list() {
		$index = Bastion_Firewall::storage()->read_php_array( 'quarantine/manifest.php' );
		uasort(
			$index,
			function ( $a, $b ) {
				return $b['time'] - $a['time'];
			}
		);
		return $index;
	}

	public static function restore_quarantined( $name ) {
		$storage = Bastion_Firewall::storage();
		$index   = $storage->read_php_array( 'quarantine/manifest.php' );
		$name    = basename( (string) $name );
		if ( ! isset( $index[ $name ] ) ) {
			return new WP_Error( 'bastion_unknown', __( 'Unknown quarantine item.', 'bastion-security' ) );
		}
		$dest = self::abs_path( $index[ $name ]['file'] );
		if ( file_exists( $dest ) ) {
			return new WP_Error( 'bastion_exists', __( 'A file already exists at the original location.', 'bastion-security' ) );
		}
		wp_mkdir_p( dirname( $dest ) );
		if ( ! @rename( $storage->path( 'quarantine/' . $name ), $dest ) ) {
			return new WP_Error( 'bastion_move_failed', __( 'Could not restore the file.', 'bastion-security' ) );
		}
		@chmod( $dest, 0644 );
		Bastion_Events::log( 'file_restored', 'Restored ' . $index[ $name ]['file'] . ' from quarantine', array( 'severity' => Bastion_Events::MEDIUM ) );
		unset( $index[ $name ] );
		$storage->write_php_array( 'quarantine/manifest.php', $index );
		return true;
	}

	/**
	 * Safety net: if PHP dies because a file Bastion quarantined is required by the site
	 * (a false positive in a theme or plugin), put the file back so the next page load works.
	 * Called from WordPress's fatal-error handler and from a shutdown fallback.
	 * Returns true when a file was put back.
	 */
	public static function rescue_from_error( $error ) {
		static $done = false;
		if ( $done || ! is_array( $error ) || empty( $error['message'] ) || ! isset( $error['type'] ) ) {
			return false;
		}
		if ( ! in_array( (int) $error['type'], array( E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR ), true ) ) {
			return false;
		}
		if ( ! preg_match( "/Failed opening required '([^']+)'/", (string) $error['message'], $m ) ) {
			return false;
		}
		$done = true;
		try {
			$missing = wp_normalize_path( $m[1] );
			foreach ( Bastion_Firewall::storage()->read_php_array( 'quarantine/manifest.php' ) as $name => $item ) {
				if ( isset( $item['file'] ) && self::abs_path( $item['file'] ) === $missing && ! file_exists( $missing ) ) {
					if ( true === self::restore_quarantined( $name ) ) {
						Bastion_Events::log(
							'file_auto_restored',
							'Put ' . $item['file'] . ' back automatically: the site needs it to run. Check it with the scanner, or update its theme or plugin.',
							array( 'severity' => Bastion_Events::HIGH )
						);
						return true;
					}
					return false;
				}
			}
		} catch ( Throwable $e ) {
			return false;
		}
		return false;
	}

	public static function delete_quarantined( $name ) {
		$storage = Bastion_Firewall::storage();
		$index   = $storage->read_php_array( 'quarantine/manifest.php' );
		$name    = basename( (string) $name );
		if ( ! isset( $index[ $name ] ) ) {
			return new WP_Error( 'bastion_unknown', __( 'Unknown quarantine item.', 'bastion-security' ) );
		}
		@unlink( $storage->path( 'quarantine/' . $name ) );
		unset( $index[ $name ] );
		$storage->write_php_array( 'quarantine/manifest.php', $index );
		return true;
	}

	/** Replace a modified/missing core or plugin file with the verified official copy. */
	public static function repair( $id ) {
		global $wp_version;
		$issue = self::get_issue( $id );
		if ( ! $issue || ! in_array( $issue->type, array( 'core_modified', 'core_missing', 'plugin_modified' ), true ) ) {
			return new WP_Error( 'bastion_not_repairable', __( 'This issue cannot be repaired automatically.', 'bastion-security' ) );
		}
		$path = self::issue_file( $issue );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		if ( 'plugin_modified' === $issue->type ) {
			if ( ! preg_match( '~^wp-content/plugins/([^/]+)/(.+)$~', $issue->file, $m ) ) {
				return new WP_Error( 'bastion_not_repairable', __( 'Unknown plugin file.', 'bastion-security' ) );
			}
			$version = isset( $issue->details['version'] ) ? $issue->details['version'] : '';
			$sums    = self::fetch_plugin_sums( $m[1], $version );
			$valid   = isset( $sums[ $m[2] ] ) ? (array) $sums[ $m[2] ] : array();
			$urls    = array(
				sprintf( 'https://plugins.svn.wordpress.org/%s/tags/%s/%s', rawurlencode( $m[1] ), rawurlencode( $version ), str_replace( '%2F', '/', rawurlencode( $m[2] ) ) ),
				sprintf( 'https://plugins.svn.wordpress.org/%s/trunk/%s', rawurlencode( $m[1] ), str_replace( '%2F', '/', rawurlencode( $m[2] ) ) ),
			);
		} else {
			$core  = self::core_sums() ? self::core_sums() : self::fetch_core_sums();
			$valid = isset( $core[ $issue->file ] ) ? array( $core[ $issue->file ] ) : array();
			$urls  = array( sprintf( 'https://core.svn.wordpress.org/tags/%s/%s', rawurlencode( $wp_version ), str_replace( '%2F', '/', rawurlencode( $issue->file ) ) ) );
		}
		if ( ! $valid ) {
			return new WP_Error( 'bastion_no_checksum', __( 'No official checksum is available for this file.', 'bastion-security' ) );
		}
		$body = null;
		foreach ( $urls as $url ) {
			$res = wp_remote_get( $url, array( 'timeout' => 20 ) );
			if ( ! is_wp_error( $res ) && 200 === wp_remote_retrieve_response_code( $res ) ) {
				$candidate = wp_remote_retrieve_body( $res );
				if ( in_array( md5( $candidate ), $valid, true ) ) {
					$body = $candidate;
					break;
				}
			}
		}
		if ( null === $body ) {
			return new WP_Error( 'bastion_download', __( 'Could not download a verified original copy of this file.', 'bastion-security' ) );
		}
		if ( is_file( $path ) ) {
			$saved = self::move_to_quarantine( $path, $issue->file, 'Backup before repair: ' . $issue->title );
			if ( is_wp_error( $saved ) ) {
				return $saved;
			}
		}
		wp_mkdir_p( dirname( $path ) );
		if ( false === file_put_contents( $path, $body ) ) {
			return new WP_Error( 'bastion_write', __( 'Could not write the file.', 'bastion-security' ) );
		}
		self::resolve_file( $issue );
		Bastion_Events::log( 'file_repaired', 'Restored official copy of ' . $issue->file . ' (modified version kept in quarantine)', array( 'severity' => Bastion_Events::MEDIUM ) );
		return true;
	}
}
