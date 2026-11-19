<?php
/**
 * IP helpers: spoof-resistant client IP detection and CIDR matching (IPv4 + IPv6).
 *
 * Standalone: must not depend on WordPress (loaded before WordPress by the firewall).
 *
 * @package Bastion_Security
 */

if ( class_exists( 'Bastion_IP', false ) ) {
	return;
}

class Bastion_IP {

	/** Published Cloudflare edge ranges. The CF-Connecting-IP header is only trusted from these. */
	const CLOUDFLARE = array(
		'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
		'108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
		'162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
		'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
		'2a06:98c0::/29', '2c0f:f248::/32',
	);

	/** Private / loopback ranges, trusted as reverse proxies by default. */
	const PRIVATE_RANGES = array(
		'10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1/128', 'fc00::/7',
	);

	public static function normalize( $ip ) {
		$ip = trim( (string) $ip );
		// Strip port from "1.2.3.4:5678" and brackets from "[::1]:80".
		if ( preg_match( '/^\[([0-9a-f:.]+)\](?::\d+)?$/i', $ip, $m ) ) {
			$ip = $m[1];
		} elseif ( substr_count( $ip, ':' ) === 1 && strpos( $ip, '.' ) !== false ) {
			$ip = substr( $ip, 0, strpos( $ip, ':' ) );
		}
		// IPv4-mapped IPv6 -> IPv4.
		if ( stripos( $ip, '::ffff:' ) === 0 && strpos( $ip, '.' ) !== false ) {
			$ip = substr( $ip, 7 );
		}
		$packed = @inet_pton( $ip );
		if ( false === $packed ) {
			return '';
		}
		return inet_ntop( $packed );
	}

	public static function is_valid( $ip ) {
		return '' !== $ip && false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * @param string $ip    Address to test.
	 * @param string $range Single address or CIDR.
	 */
	public static function in_range( $ip, $range ) {
		$range = trim( $range );
		if ( '' === $range ) {
			return false;
		}
		$ip_bin = @inet_pton( $ip );
		if ( false === $ip_bin ) {
			return false;
		}
		if ( strpos( $range, '/' ) === false ) {
			$r = @inet_pton( $range );
			return false !== $r && $r === $ip_bin;
		}
		list( $subnet, $bits ) = explode( '/', $range, 2 );
		$sub_bin = @inet_pton( trim( $subnet ) );
		if ( false === $sub_bin || strlen( $sub_bin ) !== strlen( $ip_bin ) || ! is_numeric( $bits ) ) {
			return false;
		}
		$bits = (int) $bits;
		$max  = strlen( $ip_bin ) * 8;
		if ( $bits < 0 || $bits > $max ) {
			return false;
		}
		$bytes = intdiv( $bits, 8 );
		$rem   = $bits % 8;
		if ( $bytes > 0 && substr( $ip_bin, 0, $bytes ) !== substr( $sub_bin, 0, $bytes ) ) {
			return false;
		}
		if ( $rem ) {
			$mask = ( 0xFF << ( 8 - $rem ) ) & 0xFF;
			return ( ord( $ip_bin[ $bytes ] ) & $mask ) === ( ord( $sub_bin[ $bytes ] ) & $mask );
		}
		return true;
	}

	public static function in_list( $ip, $list ) {
		if ( ! is_array( $list ) ) {
			return false;
		}
		foreach ( $list as $range ) {
			if ( self::in_range( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}

	public static function is_cloudflare( $ip ) {
		return self::in_list( $ip, self::CLOUDFLARE );
	}

	/**
	 * Determine the visitor IP. Proxy headers are only honoured when the direct peer is a
	 * proxy we trust, so attackers cannot spoof their IP by sending headers themselves.
	 *
	 * @param array  $server  $_SERVER.
	 * @param string $mode    auto | remote_addr | cloudflare | x_forwarded_for | x_real_ip.
	 * @param array  $trusted Extra trusted proxy ranges.
	 */
	public static function detect( array $server, $mode = 'auto', array $trusted = array() ) {
		$remote = self::normalize( isset( $server['REMOTE_ADDR'] ) ? $server['REMOTE_ADDR'] : '' );
		if ( '' === $remote ) {
			$remote = '0.0.0.0';
		}
		$trusted = array_merge( self::PRIVATE_RANGES, $trusted );

		switch ( $mode ) {
			case 'remote_addr':
				return $remote;

			case 'auto':
			case 'cloudflare':
				if ( ! empty( $server['HTTP_CF_CONNECTING_IP'] ) && ( self::is_cloudflare( $remote ) || self::in_list( $remote, $trusted ) ) ) {
					$cf = self::normalize( $server['HTTP_CF_CONNECTING_IP'] );
					if ( self::is_valid( $cf ) ) {
						return $cf;
					}
				}
				return $remote;

			case 'x_real_ip':
				if ( ! empty( $server['HTTP_X_REAL_IP'] ) && self::in_list( $remote, $trusted ) ) {
					$real = self::normalize( $server['HTTP_X_REAL_IP'] );
					if ( self::is_valid( $real ) ) {
						return $real;
					}
				}
				return $remote;

			case 'x_forwarded_for':
				if ( ! empty( $server['HTTP_X_FORWARDED_FOR'] ) && self::in_list( $remote, $trusted ) ) {
					// Walk right-to-left, skipping our own proxies: the first untrusted hop is the client.
					$hops = array_reverse( array_map( 'trim', explode( ',', $server['HTTP_X_FORWARDED_FOR'] ) ) );
					foreach ( $hops as $hop ) {
						$hop = self::normalize( $hop );
						if ( ! self::is_valid( $hop ) ) {
							break;
						}
						if ( ! self::in_list( $hop, $trusted ) ) {
							return $hop;
						}
					}
				}
				return $remote;
		}
		return $remote;
	}
}
