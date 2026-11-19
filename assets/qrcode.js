/**
 * Minimal QR code generator (byte mode, error correction level M, versions 1–15).
 * Used to show the authenticator setup code without loading anything from a CDN,
 * so the 2FA secret never leaves the browser.
 *
 * window.BastionQR.svg(text, {size}) -> SVG markup string
 */
( function ( root ) {
	'use strict';

	// Error-correction codewords per block and number of blocks, level M, index = version.
	var ECC = [ -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24 ];
	var BLOCKS = [ -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10 ];
	var MAX_VERSION = 15;

	function rawModules( ver ) {
		var r = ( 16 * ver + 128 ) * ver + 64;
		if ( ver >= 2 ) {
			var na = Math.floor( ver / 7 ) + 2;
			r -= ( 25 * na - 10 ) * na - 55;
			if ( ver >= 7 ) {
				r -= 36;
			}
		}
		return r;
	}

	function dataCodewords( ver ) {
		return Math.floor( rawModules( ver ) / 8 ) - ECC[ ver ] * BLOCKS[ ver ];
	}

	function gfMul( x, y ) {
		var z = 0;
		for ( var i = 7; i >= 0; i-- ) {
			z = ( z << 1 ) ^ ( ( z >>> 7 ) * 0x11d );
			z ^= ( ( y >>> i ) & 1 ) * x;
		}
		return z & 0xff;
	}

	function rsDivisor( degree ) {
		var result = [];
		for ( var i = 0; i < degree - 1; i++ ) {
			result.push( 0 );
		}
		result.push( 1 );
		var root = 1;
		for ( i = 0; i < degree; i++ ) {
			for ( var j = 0; j < result.length; j++ ) {
				result[ j ] = gfMul( result[ j ], root );
				if ( j + 1 < result.length ) {
					result[ j ] ^= result[ j + 1 ];
				}
			}
			root = gfMul( root, 0x02 );
		}
		return result;
	}

	function rsRemainder( data, divisor ) {
		var result = divisor.map( function () {
			return 0;
		} );
		data.forEach( function ( b ) {
			var factor = b ^ result.shift();
			result.push( 0 );
			divisor.forEach( function ( coef, i ) {
				result[ i ] ^= gfMul( coef, factor );
			} );
		} );
		return result;
	}

	function utf8( text ) {
		var out = [];
		var s = unescape( encodeURIComponent( text ) );
		for ( var i = 0; i < s.length; i++ ) {
			out.push( s.charCodeAt( i ) );
		}
		return out;
	}

	function encode( text ) {
		var bytes = utf8( text );
		var ver;
		for ( ver = 1; ver <= MAX_VERSION; ver++ ) {
			var cap = dataCodewords( ver ) * 8;
			var need = 4 + ( ver < 10 ? 8 : 16 ) + bytes.length * 8;
			if ( need <= cap ) {
				break;
			}
		}
		if ( ver > MAX_VERSION ) {
			throw new Error( 'Text too long for QR code' );
		}

		// Bit stream.
		var bits = [];
		function put( val, len ) {
			for ( var i = len - 1; i >= 0; i-- ) {
				bits.push( ( val >>> i ) & 1 );
			}
		}
		put( 4, 4 );
		put( bytes.length, ver < 10 ? 8 : 16 );
		bytes.forEach( function ( b ) {
			put( b, 8 );
		} );
		var capacity = dataCodewords( ver ) * 8;
		put( 0, Math.min( 4, capacity - bits.length ) );
		put( 0, ( 8 - ( bits.length % 8 ) ) % 8 );
		for ( var pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11 ) {
			put( pad, 8 );
		}
		var data = [];
		for ( var i = 0; i < bits.length; i += 8 ) {
			var byte = 0;
			for ( var j = 0; j < 8; j++ ) {
				byte = ( byte << 1 ) | bits[ i + j ];
			}
			data.push( byte );
		}

		// Error correction + interleaving.
		var numBlocks = BLOCKS[ ver ];
		var blockEcc = ECC[ ver ];
		var rawCodewords = Math.floor( rawModules( ver ) / 8 );
		var numShort = numBlocks - ( rawCodewords % numBlocks );
		var shortLen = Math.floor( rawCodewords / numBlocks );
		var divisor = rsDivisor( blockEcc );
		var blocks = [];
		for ( var b = 0, k = 0; b < numBlocks; b++ ) {
			var len = shortLen - blockEcc + ( b < numShort ? 0 : 1 );
			var dat = data.slice( k, k + len );
			k += len;
			var ecc = rsRemainder( dat, divisor );
			if ( b < numShort ) {
				dat.push( 0 );
			}
			blocks.push( dat.concat( ecc ) );
		}
		var codewords = [];
		for ( i = 0; i < blocks[ 0 ].length; i++ ) {
			for ( b = 0; b < blocks.length; b++ ) {
				if ( i !== shortLen - blockEcc || b >= numShort ) {
					codewords.push( blocks[ b ][ i ] );
				}
			}
		}

		return buildMatrix( ver, codewords );
	}

	function buildMatrix( ver, codewords ) {
		var size = ver * 4 + 17;
		var modules = [];
		var isFn = [];
		for ( var y = 0; y < size; y++ ) {
			modules.push( new Array( size ).fill( false ) );
			isFn.push( new Array( size ).fill( false ) );
		}
		function setFn( x, y, dark ) {
			modules[ y ][ x ] = dark;
			isFn[ y ][ x ] = true;
		}

		// Timing patterns.
		for ( var i = 0; i < size; i++ ) {
			setFn( 6, i, i % 2 === 0 );
			setFn( i, 6, i % 2 === 0 );
		}
		// Finder patterns + separators.
		[ [ 3, 3 ], [ size - 4, 3 ], [ 3, size - 4 ] ].forEach( function ( c ) {
			for ( var dy = -4; dy <= 4; dy++ ) {
				for ( var dx = -4; dx <= 4; dx++ ) {
					var xx = c[ 0 ] + dx;
					var yy = c[ 1 ] + dy;
					if ( xx >= 0 && xx < size && yy >= 0 && yy < size ) {
						var dist = Math.max( Math.abs( dx ), Math.abs( dy ) );
						setFn( xx, yy, dist !== 2 && dist !== 4 );
					}
				}
			}
		} );
		// Alignment patterns.
		var pos = alignmentPositions( ver );
		var n = pos.length;
		for ( var a = 0; a < n; a++ ) {
			for ( var bIdx = 0; bIdx < n; bIdx++ ) {
				if ( ( a === 0 && bIdx === 0 ) || ( a === 0 && bIdx === n - 1 ) || ( a === n - 1 && bIdx === 0 ) ) {
					continue;
				}
				for ( var dy2 = -2; dy2 <= 2; dy2++ ) {
					for ( var dx2 = -2; dx2 <= 2; dx2++ ) {
						setFn( pos[ a ] + dx2, pos[ bIdx ] + dy2, Math.max( Math.abs( dx2 ), Math.abs( dy2 ) ) !== 1 );
					}
				}
			}
		}
		// Reserve format areas (real bits drawn per mask) and draw version info.
		drawFormat( modules, isFn, size, 0, setFn );
		if ( ver >= 7 ) {
			var rem = ver;
			for ( i = 0; i < 12; i++ ) {
				rem = ( rem << 1 ) ^ ( ( rem >>> 11 ) * 0x1f25 );
			}
			var vbits = ( ver << 12 ) | rem;
			for ( i = 0; i < 18; i++ ) {
				var bit = ( ( vbits >>> i ) & 1 ) !== 0;
				var p = size - 11 + ( i % 3 );
				var q = Math.floor( i / 3 );
				setFn( p, q, bit );
				setFn( q, p, bit );
			}
		}

		// Data (zigzag).
		var bitIndex = 0;
		var total = codewords.length * 8;
		for ( var right = size - 1; right >= 1; right -= 2 ) {
			if ( right === 6 ) {
				right = 5;
			}
			for ( var vert = 0; vert < size; vert++ ) {
				for ( var j = 0; j < 2; j++ ) {
					var x = right - j;
					var upward = ( ( right + 1 ) & 2 ) === 0;
					var yy2 = upward ? size - 1 - vert : vert;
					if ( ! isFn[ yy2 ][ x ] && bitIndex < total ) {
						modules[ yy2 ][ x ] = ( ( codewords[ bitIndex >>> 3 ] >>> ( 7 - ( bitIndex & 7 ) ) ) & 1 ) !== 0;
						bitIndex++;
					}
				}
			}
		}

		// Pick the mask with the lowest penalty.
		var best = 0;
		var bestPenalty = Infinity;
		for ( var m = 0; m < 8; m++ ) {
			applyMask( modules, isFn, size, m );
			drawFormat( modules, isFn, size, m, setFn );
			var pen = penalty( modules, size );
			if ( pen < bestPenalty ) {
				bestPenalty = pen;
				best = m;
			}
			applyMask( modules, isFn, size, m ); // Undo (XOR).
		}
		applyMask( modules, isFn, size, best );
		drawFormat( modules, isFn, size, best, setFn );
		return modules;
	}

	function alignmentPositions( ver ) {
		if ( ver === 1 ) {
			return [];
		}
		var num = Math.floor( ver / 7 ) + 2;
		var step = ver === 32 ? 26 : Math.ceil( ( ver * 4 + 4 ) / ( num * 2 - 2 ) ) * 2;
		var result = [ 6 ];
		for ( var p = ver * 4 + 10; result.length < num; p -= step ) {
			result.splice( 1, 0, p );
		}
		return result;
	}

	function drawFormat( modules, isFn, size, mask, setFn ) {
		var data = ( 0 << 3 ) | mask; // Level M = 0b00.
		var rem = data;
		for ( var i = 0; i < 10; i++ ) {
			rem = ( rem << 1 ) ^ ( ( rem >>> 9 ) * 0x537 );
		}
		var bits = ( ( data << 10 ) | rem ) ^ 0x5412;
		function bit( k ) {
			return ( ( bits >>> k ) & 1 ) !== 0;
		}
		for ( i = 0; i <= 5; i++ ) {
			setFn( 8, i, bit( i ) );
		}
		setFn( 8, 7, bit( 6 ) );
		setFn( 8, 8, bit( 7 ) );
		setFn( 7, 8, bit( 8 ) );
		for ( i = 9; i < 15; i++ ) {
			setFn( 14 - i, 8, bit( i ) );
		}
		for ( i = 0; i < 8; i++ ) {
			setFn( size - 1 - i, 8, bit( i ) );
		}
		for ( i = 8; i < 15; i++ ) {
			setFn( 8, size - 15 + i, bit( i ) );
		}
		setFn( 8, size - 8, true ); // Dark module.
	}

	function applyMask( modules, isFn, size, mask ) {
		for ( var y = 0; y < size; y++ ) {
			for ( var x = 0; x < size; x++ ) {
				if ( isFn[ y ][ x ] ) {
					continue;
				}
				var invert;
				switch ( mask ) {
					case 0: invert = ( x + y ) % 2 === 0; break;
					case 1: invert = y % 2 === 0; break;
					case 2: invert = x % 3 === 0; break;
					case 3: invert = ( x + y ) % 3 === 0; break;
					case 4: invert = ( Math.floor( x / 3 ) + Math.floor( y / 2 ) ) % 2 === 0; break;
					case 5: invert = ( ( x * y ) % 2 ) + ( ( x * y ) % 3 ) === 0; break;
					case 6: invert = ( ( ( x * y ) % 2 ) + ( ( x * y ) % 3 ) ) % 2 === 0; break;
					default: invert = ( ( ( x + y ) % 2 ) + ( ( x * y ) % 3 ) ) % 2 === 0;
				}
				if ( invert ) {
					modules[ y ][ x ] = ! modules[ y ][ x ];
				}
			}
		}
	}

	// Simplified penalty (runs, 2x2 blocks, balance). Any mask decodes; this only improves scanning.
	function penalty( modules, size ) {
		var score = 0;
		var dark = 0;
		for ( var y = 0; y < size; y++ ) {
			for ( var dir = 0; dir < 2; dir++ ) {
				var run = 1;
				for ( var x = 1; x < size; x++ ) {
					var a = dir ? modules[ x ][ y ] : modules[ y ][ x ];
					var b = dir ? modules[ x - 1 ][ y ] : modules[ y ][ x - 1 ];
					if ( a === b ) {
						run++;
						if ( run === 5 ) {
							score += 3;
						} else if ( run > 5 ) {
							score++;
						}
					} else {
						run = 1;
					}
				}
			}
			for ( x = 0; x < size; x++ ) {
				if ( modules[ y ][ x ] ) {
					dark++;
				}
				if ( y < size - 1 && x < size - 1 ) {
					var c = modules[ y ][ x ];
					if ( c === modules[ y ][ x + 1 ] && c === modules[ y + 1 ][ x ] && c === modules[ y + 1 ][ x + 1 ] ) {
						score += 3;
					}
				}
			}
		}
		var total = size * size;
		score += Math.floor( Math.abs( dark * 20 - total * 10 ) / total ) * 10;
		return score;
	}

	function svg( text, opts ) {
		opts = opts || {};
		var m = encode( text );
		var size = m.length;
		var quiet = 4;
		var dim = size + quiet * 2;
		var path = '';
		for ( var y = 0; y < size; y++ ) {
			for ( var x = 0; x < size; x++ ) {
				if ( m[ y ][ x ] ) {
					path += 'M' + ( x + quiet ) + ',' + ( y + quiet ) + 'h1v1h-1z';
				}
			}
		}
		var px = opts.size || 220;
		return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + dim + ' ' + dim + '" width="' + px + '" height="' + px + '" shape-rendering="crispEdges" role="img" aria-label="QR code">' +
			'<rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="' + path + '"/></svg>';
	}

	root.BastionQR = { encode: encode, svg: svg };
} )( typeof window !== 'undefined' ? window : globalThis );
