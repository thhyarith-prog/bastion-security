/**
 * Bastion comment shield: fetches a one-time token for the comment form when someone starts
 * writing, so spam bots that post straight to wp-comments-post.php are stopped. The token is
 * never part of the page, so cached pages work. Covers the core form and theme forms that post
 * to wp-comments-post.php.
 */
( function () {
	'use strict';
	var C = window.BastionComments;
	if ( ! C || ! window.fetch ) {
		return;
	}
	var SELECTOR = 'form#commentform, form[action*="wp-comments-post.php"]';
	var tokens = {}; // post id -> { t, at }
	var pending = {};

	function postOf( form ) {
		var input = form.querySelector( '[name="comment_post_ID"]' );
		return input && input.value ? input.value : String( C.post || '' );
	}

	function field( form ) {
		var f = form.querySelector( 'input[name="bastion_ct"]' );
		if ( ! f ) {
			f = document.createElement( 'input' );
			f.type = 'hidden';
			f.name = 'bastion_ct';
			form.appendChild( f );
		}
		return f;
	}

	function fetchToken( post ) {
		if ( pending[ post ] ) {
			return pending[ post ];
		}
		pending[ post ] = fetch( C.ajax, {
			method: 'POST',
			credentials: 'same-origin',
			cache: 'no-store',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: 'action=bastion_ct&p=' + encodeURIComponent( post )
		} )
			.then( function ( r ) { return r.ok ? r.json() : null; } )
			.then( function ( j ) {
				if ( j && j.success && j.data && j.data.t ) {
					tokens[ post ] = { t: j.data.t, at: Date.now() };
				}
				return tokens[ post ] || null;
			} )
			.catch( function () { return null; } )
			.then( function ( tok ) { delete pending[ post ]; return tok; } );
		return pending[ post ];
	}

	function fresh( post ) {
		var tok = tokens[ post ];
		return tok && Date.now() - tok.at < 12 * 3600 * 1000 ? tok : null;
	}

	function prime( form ) {
		var post = postOf( form );
		if ( ! post || fresh( post ) ) {
			if ( fresh( post ) ) {
				field( form ).value = tokens[ post ].t;
			}
			return;
		}
		fetchToken( post ).then( function ( tok ) {
			field( form ).value = tok ? tok.t : 'js:' + Date.now();
		} );
	}

	function send( form, submitter ) {
		form.dataset.bastionOk = '1';
		if ( form.requestSubmit ) {
			form.requestSubmit( submitter && submitter.form === form ? submitter : undefined );
		} else {
			HTMLFormElement.prototype.submit.call( form );
		}
	}

	document.addEventListener( 'focusin', function ( e ) {
		var form = e.target && e.target.closest ? e.target.closest( SELECTOR ) : null;
		if ( form ) {
			prime( form );
		}
	} );

	document.addEventListener( 'submit', function ( e ) {
		var form = e.target;
		if ( ! form || ! form.matches || ! form.matches( SELECTOR ) ) {
			return;
		}
		if ( form.dataset.bastionOk === '1' ) {
			delete form.dataset.bastionOk;
			return; // Our own resubmit: let it (and any theme handler) through.
		}
		var post = postOf( form );
		var tok = fresh( post );
		var wait = tok ? Math.max( 0, ( C.min || 0 ) * 1000 + 300 - ( Date.now() - tok.at ) ) : 0;
		if ( tok && wait === 0 ) {
			field( form ).value = tok.t;
			return;
		}
		e.preventDefault();
		e.stopImmediatePropagation();
		var button = e.submitter || form.querySelector( '[type="submit"]' );
		var label = button ? ( button.value || button.textContent ) : '';
		if ( button ) {
			button.disabled = true;
			if ( button.tagName === 'INPUT' ) { button.value = C.posting; } else { button.textContent = C.posting; }
		}
		var ready = tok ? Promise.resolve( tok ) : fetchToken( post );
		ready.then( function ( t ) {
			field( form ).value = t ? t.t : 'js:' + Date.now();
			var left = t ? Math.max( 0, ( C.min || 0 ) * 1000 + 300 - ( Date.now() - t.at ) ) : 0;
			setTimeout( function () {
				if ( button ) {
					button.disabled = false;
					if ( button.tagName === 'INPUT' ) { button.value = label; } else { button.textContent = label; }
				}
				send( form, button );
			}, left );
		} );
	}, true );

	// Fetch early when the form scrolls into view, so most people never wait.
	if ( 'IntersectionObserver' in window ) {
		var io = new IntersectionObserver( function ( entries ) {
			entries.forEach( function ( en ) {
				if ( en.isIntersecting ) {
					io.unobserve( en.target );
					prime( en.target );
				}
			} );
		}, { rootMargin: '200px' } );
		var watch = function () {
			document.querySelectorAll( SELECTOR ).forEach( function ( f ) { io.observe( f ); } );
		};
		if ( document.readyState === 'loading' ) {
			document.addEventListener( 'DOMContentLoaded', watch );
		} else {
			watch();
		}
	}
} )();
