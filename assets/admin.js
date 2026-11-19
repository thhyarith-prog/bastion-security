/* Bastion Security admin UI. No dependencies. */
( function () {
	'use strict';

	var cfg = window.BastionAdmin || {};
	var t = cfg.i18n || {};

	function post( action, data, nonce ) {
		var body = new FormData();
		body.append( 'action', action );
		body.append( 'nonce', nonce || cfg.nonce );
		Object.keys( data || {} ).forEach( function ( k ) {
			body.append( k, data[ k ] );
		} );
		return fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } )
			.then( function ( r ) {
				return r.json();
			} )
			.then( function ( json ) {
				if ( ! json || ! json.success ) {
					throw new Error( ( json && json.data && json.data.message ) || t.error );
				}
				return json.data || {};
			} );
	}

	function esc( s ) {
		var d = document.createElement( 'div' );
		d.textContent = s == null ? '' : String( s );
		return d.innerHTML;
	}

	/* ------------------------------------------------------------- scanner */

	var scan = document.querySelector( '.bastion-scan' );
	if ( scan ) {
		var startBtn = scan.querySelector( '.bastion-scan__start' );
		var stopBtn = scan.querySelector( '.bastion-scan__stop' );
		var progress = scan.querySelector( '.bastion-progress' );
		var bar = scan.querySelector( '.bastion-progress__bar span' );
		var msg = scan.querySelector( '.bastion-progress__msg' );
		var stopped = false;
		var fails = 0;

		var render = function ( s ) {
			progress.hidden = false;
			bar.style.width = ( s.percent || 0 ) + '%';
			msg.textContent = s.message || t.scanning;
		};

		var loop = function () {
			if ( stopped ) {
				return;
			}
			post( 'bastion_scan_step' )
				.then( function ( s ) {
					fails = 0;
					render( s );
					if ( s.status === 'running' ) {
						setTimeout( loop, 400 );
					} else {
						setTimeout( function () {
							window.location.reload();
						}, 800 );
					}
				} )
				.catch( function ( e ) {
					msg.textContent = e.message;
					fails++;
					if ( fails < 6 && ! /expired|Not allowed|-1/i.test( e.message ) ) {
						setTimeout( loop, 4000 ); // Transient server hiccup: keep going.
					} else {
						stopBtn.hidden = true;
						startBtn.hidden = false; // Give control back; the scan resumes server-side on the next start.
					}
				} );
		};

		startBtn.addEventListener( 'click', function () {
			stopped = false;
			startBtn.hidden = true;
			stopBtn.hidden = false;
			render( { percent: 1, message: t.scanning } );
			post( 'bastion_scan_start' )
				.then( function ( s ) {
					render( s );
					loop();
				} )
				.catch( function ( e ) {
					msg.textContent = e.message;
					startBtn.hidden = false;
					stopBtn.hidden = true;
				} );
		} );

		stopBtn.addEventListener( 'click', function () {
			stopped = true;
			stopBtn.setAttribute( 'aria-busy', 'true' );
			post( 'bastion_scan_stop' )
				.then( function () {
					window.location.reload();
				} )
				.catch( function ( e ) {
					stopBtn.removeAttribute( 'aria-busy' );
					msg.textContent = e.message;
				} );
		} );

		if ( scan.dataset.running === '1' ) {
			loop();
		}
	}

	/* -------------------------------------------------------------- issues */

	var dialog = document.getElementById( 'bastion-file-dialog' );

	function showFile( data ) {
		if ( ! dialog ) {
			return;
		}
		dialog.querySelector( '.bastion-dialog__title' ).textContent = data.file;
		dialog.querySelector( '.bastion-dialog__meta' ).textContent =
			data.size + ' bytes · ' + data.modified + ( data.truncated ? ' · (truncated)' : '' );
		var lines = String( data.content ).split( '\n' );
		var html = lines
			.map( function ( l, i ) {
				var n = i + 1;
				return '<div class="bastion-code__line' + ( n === data.line ? ' is-hit' : '' ) + '"><span>' + n + '</span><code>' + esc( l ) + '</code></div>';
			} )
			.join( '' );
		var box = dialog.querySelector( '.bastion-code' );
		box.innerHTML = html;
		dialog.showModal();
		var hit = box.querySelector( '.is-hit' );
		if ( hit ) {
			hit.scrollIntoView( { block: 'center' } );
		}
	}

	document.addEventListener( 'click', function ( ev ) {
		var btn = ev.target.closest( '[data-issue]' );
		if ( ! btn ) {
			return;
		}
		var item = btn.closest( '.bastion-issue' );
		var action = btn.getAttribute( 'data-issue' );
		var out = item.querySelector( '.bastion-issue__msg' );
		if ( action === 'quarantine' && ! window.confirm( t.confirmQuarantine ) ) {
			return;
		}
		if ( action === 'repair' && ! window.confirm( t.confirmRepair ) ) {
			return;
		}
		btn.disabled = true;
		out.textContent = '…';
		post( 'bastion_issue', { id: item.getAttribute( 'data-id' ), do: action } )
			.then( function ( res ) {
				btn.disabled = false;
				if ( action === 'view' ) {
					out.textContent = '';
					showFile( res );
					return;
				}
				out.textContent = res.message || '';
				item.classList.add( 'is-done' );
				setTimeout( function () {
					item.remove();
				}, 1200 );
			} )
			.catch( function ( e ) {
				btn.disabled = false;
				out.textContent = e.message;
				out.classList.add( 'is-error' );
			} );
	} );

	document.addEventListener( 'click', function ( ev ) {
		var btn = ev.target.closest( '[data-quarantine]' );
		if ( ! btn ) {
			return;
		}
		var row = btn.closest( 'tr' );
		var action = btn.getAttribute( 'data-quarantine' );
		if ( action === 'delete' && ! window.confirm( t.confirmDelete ) ) {
			return;
		}
		btn.disabled = true;
		post( 'bastion_quarantine', { name: row.getAttribute( 'data-q' ), do: action } )
			.then( function () {
				row.remove();
			} )
			.catch( function ( e ) {
				btn.disabled = false;
				window.alert( e.message );
			} );
	} );

	/* --------------------------------------------------------- two-factor */

	var tfa = document.querySelector( '.bastion-tfa' );
	if ( tfa ) {
		var panel = tfa.querySelector( '.bastion-tfa-panel' );
		var nonce = tfa.dataset.nonce;
		var userId = tfa.dataset.user;

		var codeInput = function () {
			var el = tfa.querySelector( '.bastion-tfa-code' );
			return el ? el.value : '';
		};

		var showError = function ( where, message ) {
			var p = where.querySelector( '.bastion-tfa-error' );
			if ( ! p ) {
				p = document.createElement( 'p' );
				p.className = 'bastion-tfa-error';
				p.setAttribute( 'role', 'alert' );
				where.appendChild( p );
			}
			p.textContent = message;
		};

		var showCodes = function ( codes ) {
			var text = codes.join( '\n' );
			panel.hidden = false;
			panel.innerHTML =
				'<h3>' + esc( t.backupTitle ) + '</h3><p>' + esc( t.backupHelp ) + '</p>' +
				'<ol class="bastion-codes">' + codes.map( function ( c ) {
					return '<li><code>' + esc( c ) + '</code></li>';
				} ).join( '' ) + '</ol>' +
				'<p><button type="button" class="button" data-act="copy">' + esc( t.copy ) + '</button> ' +
				'<button type="button" class="button" data-act="download">' + esc( t.download ) + '</button> ' +
				'<button type="button" class="button button-primary" data-act="done">' + esc( t.done ) + '</button></p>';
			panel.querySelector( '[data-act="copy"]' ).addEventListener( 'click', function ( e ) {
				navigator.clipboard.writeText( text ).then( function () {
					e.target.textContent = t.copied;
				} );
			} );
			panel.querySelector( '[data-act="download"]' ).addEventListener( 'click', function () {
				var a = document.createElement( 'a' );
				a.href = URL.createObjectURL( new Blob( [ window.location.hostname + ' backup codes\n\n' + text + '\n' ], { type: 'text/plain' } ) );
				a.download = 'backup-codes-' + window.location.hostname + '.txt';
				a.click();
			} );
			panel.querySelector( '[data-act="done"]' ).addEventListener( 'click', function () {
				window.location.reload();
			} );
		};

		tfa.addEventListener( 'click', function ( ev ) {
			var btn = ev.target.closest( '[data-tfa]' );
			if ( ! btn ) {
				return;
			}
			ev.preventDefault();
			var act = btn.getAttribute( 'data-tfa' );

			if ( act === 'begin' ) {
				btn.disabled = true;
				post( 'bastion_tfa_begin', {}, nonce )
					.then( function ( res ) {
						var qr = '';
						try {
							qr = window.BastionQR.svg( res.uri, { size: 200 } );
						} catch ( e ) {}
						panel.hidden = false;
						panel.innerHTML =
							'<div class="bastion-tfa-setup"><div class="bastion-tfa-qr">' + qr + '</div><div>' +
							'<p><strong>' + esc( t.scanQR ) + '</strong></p>' +
							'<p>' + esc( t.orKey ) + '<br><code class="bastion-secret">' + esc( res.secret ) + '</code></p>' +
							'<p><label for="bastion-tfa-confirm"><strong>' + esc( t.enterCode ) + '</strong></label><br>' +
							'<input id="bastion-tfa-confirm" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="7" class="regular-text" style="max-width:140px;font-size:20px;letter-spacing:.15em"></p>' +
							'<p><button type="button" class="button button-primary" data-tfa="confirm">' + esc( t.verify ) + '</button> ' +
							'<button type="button" class="button-link" data-tfa="cancel">' + esc( t.cancel ) + '</button></p></div></div>';
						panel.querySelector( '#bastion-tfa-confirm' ).focus();
					} )
					.catch( function ( e ) {
						btn.disabled = false;
						showError( tfa, e.message );
					} );
			} else if ( act === 'confirm' ) {
				btn.disabled = true;
				post( 'bastion_tfa_confirm', { code: panel.querySelector( '#bastion-tfa-confirm' ).value }, nonce )
					.then( function ( res ) {
						showCodes( res.codes );
					} )
					.catch( function ( e ) {
						btn.disabled = false;
						showError( panel, e.message );
					} );
			} else if ( act === 'cancel' ) {
				window.location.reload();
			} else if ( act === 'disable' ) {
				if ( ! window.confirm( t.confirmDisable2fa ) ) {
					return;
				}
				post( 'bastion_tfa_disable', { code: codeInput(), user: userId }, nonce )
					.then( function () {
						window.location.reload();
					} )
					.catch( function ( e ) {
						showError( tfa, e.message );
					} );
			} else if ( act === 'regen' ) {
				post( 'bastion_tfa_regen', { code: codeInput() }, nonce )
					.then( function ( res ) {
						showCodes( res.codes );
					} )
					.catch( function ( e ) {
						showError( tfa, e.message );
					} );
			}
		} );

		// Pressing Enter inside the setup code field should verify, not submit the profile form.
		tfa.addEventListener( 'keydown', function ( ev ) {
			if ( ev.key === 'Enter' && ev.target.matches( 'input' ) ) {
				ev.preventDefault();
				var confirmBtn = tfa.querySelector( '[data-tfa="confirm"]' );
				if ( confirmBtn ) {
					confirmBtn.click();
				}
			}
		} );
	}
	/* ------------------------------------------------------- comment clean-up */

	var cleanup = document.querySelector( '.bastion-cleanup' );
	if ( cleanup ) {
		var cCheck = cleanup.querySelector( '.bastion-cleanup__check' );
		var cApply = cleanup.querySelector( '.bastion-cleanup__apply' );
		var cEmpty = cleanup.querySelector( '.bastion-cleanup__empty' );
		var cStatus = cleanup.querySelector( '.bastion-cleanup__status' );
		var cProg = cleanup.querySelector( '.bastion-progress' );
		var cBar = cleanup.querySelector( '.bastion-progress__bar span' );
		var cSamples = cleanup.querySelector( '.bastion-cleanup__samples' );
		var total = parseInt( cleanup.getAttribute( 'data-pending' ), 10 ) || 0;
		var fmt = function ( s ) {
			var a = Array.prototype.slice.call( arguments, 1 );
			return String( s ).replace( /%(\d)\$s|%s/g, function ( m, n ) {
				return n ? a[ n - 1 ] : a.shift();
			} );
		};
		var num = function ( n ) {
			return Number( n ).toLocaleString();
		};
		var busy = function ( on ) {
			[ cCheck, cApply, cEmpty ].forEach( function ( b ) {
				if ( b ) {
					b.disabled = on;
				}
			} );
			cleanup.setAttribute( 'aria-busy', on ? 'true' : 'false' );
			if ( cProg ) {
				cProg.hidden = ! on;
			}
		};
		var runScan = function ( apply ) {
			var cursor = 0, scanned = 0, spam = 0;
			busy( true );
			if ( cSamples && ! apply ) {
				cSamples.innerHTML = '';
			}
			var step = function () {
				return post( 'bastion_spam_scan', { cursor: cursor, apply: apply ? 1 : 0 } ).then( function ( r ) {
					cursor = r.cursor;
					scanned += r.scanned;
					spam += r.spam;
					if ( cBar ) {
						cBar.style.width = Math.min( 100, Math.round( 100 * scanned / Math.max( 1, total ) ) ) + '%';
					}
					cStatus.textContent = fmt( t.checking, num( scanned ), num( total ) );
					if ( ! apply && cSamples && r.samples ) {
						r.samples.forEach( function ( sm ) {
							if ( cSamples.children.length < 6 ) {
								var li = document.createElement( 'li' );
								li.innerHTML = '<div><span>' + esc( sm.text ) + '</span><small>' + esc( sm.author ) + '</small></div>';
								cSamples.appendChild( li );
							}
						} );
					}
					return r.done ? r : step();
				} );
			};
			return step().then( function () {
				busy( false );
				if ( apply ) {
					cStatus.textContent = fmt( t.moved, num( spam ) );
					if ( cApply ) {
						cApply.hidden = true;
					}
					if ( cEmpty && spam ) {
						cEmpty.hidden = false;
					}
				} else {
					cStatus.textContent = fmt( t.checked, num( spam ), num( scanned ) );
					if ( cApply ) {
						cApply.hidden = ! spam;
					}
				}
			} ).catch( function ( e ) {
				busy( false );
				cStatus.textContent = e.message;
			} );
		};
		if ( cCheck ) {
			cCheck.addEventListener( 'click', function () {
				runScan( false );
			} );
		}
		if ( cApply ) {
			cApply.addEventListener( 'click', function () {
				if ( window.confirm( t.confirmSpamApply ) ) {
					runScan( true );
				}
			} );
		}
		if ( cEmpty ) {
			cEmpty.addEventListener( 'click', function () {
				if ( ! window.confirm( t.confirmSpamEmpty ) ) {
					return;
				}
				var deleted = 0;
				busy( true );
				var step = function () {
					return post( 'bastion_spam_empty', {} ).then( function ( r ) {
						deleted += r.deleted;
						cStatus.textContent = fmt( t.deleting, num( deleted ) );
						return r.done ? r : step();
					} );
				};
				step().then( function () {
					busy( false );
					cStatus.textContent = fmt( t.deleted, num( deleted ) );
					cEmpty.hidden = true;
				} ).catch( function ( e ) {
					busy( false );
					cStatus.textContent = e.message;
				} );
			} );
		}
	}

	/* ------------------------------------------------------------- visitors */

	var live = document.querySelector( '.bastion-visitors[data-live]' );
	if ( live ) {
		var fmtN = function ( s, n ) {
			return String( s ).replace( '%s', Number( n ).toLocaleString() );
		};
		var refresh = function () {
			if ( document.visibilityState !== 'visible' ) {
				return;
			}
			post( 'bastion_visitors_live', {} ).then( function ( r ) {
				var set = function ( k, v ) {
					var el = document.querySelector( '[data-v="' + k + '"]' );
					if ( el ) {
						el.textContent = Number( v ).toLocaleString();
					}
				};
				set( 'live', r.live );
				set( 'visitors', r.today.visitors );
				set( 'views', r.today.views );
				var list = document.querySelector( '[data-v="pages"]' );
				if ( list && r.pages ) {
					list.innerHTML = r.pages.length ? r.pages.map( function ( p ) {
						return '<li><div><span>' + esc( p.path ) + '</span><small>' + esc( fmtN( p.n === 1 ? t.visitor : t.visitors, p.n ) ) + '</small></div></li>';
					} ).join( '' ) : '<li class="bastion-empty">' + esc( t.nobody ) + '</li>';
				}
			} ).catch( function () {} );
		};
		setInterval( refresh, 30000 );
		document.addEventListener( 'visibilitychange', refresh );
	}
} )();
