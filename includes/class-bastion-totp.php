<?php
/**
 * RFC 6238 TOTP / RFC 4226 HOTP and secret encryption helpers.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

class Bastion_TOTP {

	const PERIOD = 30;
	const DIGITS = 6;
	const B32    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	public static function generate_secret( $bytes = 20 ) {
		return self::base32_encode( random_bytes( $bytes ) );
	}

	public static function base32_encode( $data ) {
		$bits = '';
		foreach ( str_split( $data ) as $c ) {
			$bits .= str_pad( decbin( ord( $c ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::B32[ bindec( str_pad( $chunk, 5, '0' ) ) ];
		}
		return $out;
	}

	public static function base32_decode( $b32 ) {
		$b32  = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', (string) $b32 ) );
		$bits = '';
		foreach ( str_split( $b32 ) as $c ) {
			$bits .= str_pad( decbin( strpos( self::B32, $c ) ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	public static function hotp( $secret_b32, $counter ) {
		$key  = self::base32_decode( $secret_b32 );
		$msg  = pack( 'N2', ( $counter >> 32 ) & 0xFFFFFFFF, $counter & 0xFFFFFFFF );
		$hash = hash_hmac( 'sha1', $msg, $key, true );
		$off  = ord( $hash[19] ) & 0x0F;
		$bin  = ( ( ord( $hash[ $off ] ) & 0x7F ) << 24 ) | ( ord( $hash[ $off + 1 ] ) << 16 ) | ( ord( $hash[ $off + 2 ] ) << 8 ) | ord( $hash[ $off + 3 ] );
		return str_pad( (string) ( $bin % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	public static function counter( $time = null ) {
		return (int) floor( ( null === $time ? time() : $time ) / self::PERIOD );
	}

	/**
	 * Verify a code within ±$window steps, rejecting counters at or below $last_used (replay).
	 *
	 * @return int|false Matching counter or false.
	 */
	public static function verify( $secret_b32, $code, $last_used = 0, $window = 1 ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}
		$now = self::counter();
		for ( $i = -$window; $i <= $window; $i++ ) {
			$c = $now + $i;
			if ( $c <= (int) $last_used ) {
				continue;
			}
			if ( hash_equals( self::hotp( $secret_b32, $c ), $code ) ) {
				return $c;
			}
		}
		return false;
	}

	public static function uri( $secret, $account, $issuer ) {
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );
		return 'otpauth://totp/' . $label . '?secret=' . $secret . '&issuer=' . rawurlencode( $issuer ) . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
	}

	/* ------------------------------------------------- encryption at rest */

	private static function key() {
		$material = defined( 'BASTION_ENCRYPTION_KEY' ) ? BASTION_ENCRYPTION_KEY : ( defined( 'AUTH_KEY' ) ? AUTH_KEY : '' ) . ( defined( 'SECURE_AUTH_SALT' ) ? SECURE_AUTH_SALT : '' );
		return hash( 'sha256', 'bastion-2fa|' . $material, true );
	}

	public static function encrypt( $plain ) {
		if ( ! function_exists( 'openssl_encrypt' ) ) {
			return 'p:' . $plain;
		}
		$iv  = random_bytes( 12 );
		$tag = '';
		$ct  = openssl_encrypt( $plain, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag );
		return 'g:' . base64_encode( $iv . $tag . $ct );
	}

	/** @return string|false */
	public static function decrypt( $stored ) {
		$stored = (string) $stored;
		if ( 0 === strpos( $stored, 'p:' ) ) {
			return substr( $stored, 2 );
		}
		if ( 0 !== strpos( $stored, 'g:' ) || ! function_exists( 'openssl_decrypt' ) ) {
			return false;
		}
		$raw = base64_decode( substr( $stored, 2 ), true );
		if ( false === $raw || strlen( $raw ) < 29 ) {
			return false;
		}
		$out = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ) );
		return false === $out ? false : $out;
	}
}
