/* PHP2Shell & wp2shell Scanner admin. No dependencies. */
( function () {
	'use strict';

	var cfg = window.WP2SS;
	if ( ! cfg ) {
		return;
	}

	function post( action, data ) {
		var body = new FormData();
		body.append( 'action', action );
		body.append( 'nonce', cfg.nonce );
		Object.keys( data || {} ).forEach( function ( k ) {
			body.append( k, data[ k ] );
		} );
		return fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) {
			return r.text().then( function ( t ) {
				var json;
				try {
					json = JSON.parse( t );
				} catch ( e ) {
					// Fatal errors and host timeouts come back as HTML.
					throw new Error( r.status ? 'HTTP ' + r.status : 'Network error' );
				}
				if ( ! json.success ) {
					throw new Error( ( json.data && json.data.message ) || 'Request failed' );
				}
				return json.data;
			} );
		} );
	}

	/* ---------------- Scan with progress ---------------- */

	var btn = document.getElementById( 'wp2ss-scan' );
	var box = document.getElementById( 'wp2ss-progress' );

	if ( btn && box ) {
		var bar = box.querySelector( '.wp2ss-bar' );
		var fill = bar.querySelector( 'span' );
		var text = box.querySelector( '.wp2ss-progress-text' );
		var cancel = document.getElementById( 'wp2ss-cancel' );
		var stopped = false;
		var failures = 0;

		var show = function ( pct, msg ) {
			pct = Math.max( 2, Math.min( 100, pct ) );
			box.hidden = false;
			fill.style.width = pct + '%';
			bar.setAttribute( 'aria-valuenow', String( Math.round( pct ) ) );
			text.textContent = msg;
		};

		var label = function ( d ) {
			var m = cfg.i18n[ d.phase ] || cfg.i18n.files;
			if ( d.phase === 'files' && d.files ) {
				m += ' (' + d.files.toLocaleString() + ')';
			}
			return m;
		};

		var loop = function () {
			if ( stopped ) {
				return;
			}
			post( 'wp2ss_step' )
				.then( function ( d ) {
					failures = 0;
					if ( d.busy ) {
						// Another tab or a scheduled scan is mid-slice: wait our turn.
						text.textContent = cfg.i18n.waiting;
						setTimeout( loop, 1500 );
						return;
					}
					if ( d.done ) {
						show( 100, cfg.i18n.done );
						window.location.reload();
						return;
					}
					show( d.progress, label( d ) );
					loop();
				} )
				.catch( function ( e ) {
					// Transient host hiccups are common on shared hosting: retry a few times.
					if ( ++failures <= 3 ) {
						text.textContent = cfg.i18n.retry;
						setTimeout( loop, 2000 * failures );
						return;
					}
					text.textContent = cfg.i18n.error + ' ' + e.message;
					btn.disabled = false;
				} );
		};

		btn.addEventListener( 'click', function ( e ) {
			e.preventDefault();
			stopped = false;
			failures = 0;
			btn.disabled = true;
			show( 1, cfg.i18n.starting );
			post( 'wp2ss_start', { force: 1 } )
				.then( function ( d ) {
					if ( d.done ) {
						window.location.reload();
						return;
					}
					show( d.progress, label( d ) );
					loop();
				} )
				.catch( function ( err ) {
					text.textContent = cfg.i18n.error + ' ' + err.message;
					btn.disabled = false;
				} );
		} );

		if ( cancel ) {
			cancel.addEventListener( 'click', function () {
				stopped = true;
				post( 'wp2ss_cancel' ).finally( function () {
					box.hidden = true;
					btn.disabled = false;
				} );
			} );
		}

		// A scheduled scan is already running: attach to it.
		if ( btn.getAttribute( 'data-running' ) ) {
			btn.disabled = true;
			show( 5, cfg.i18n.files );
			loop();
		}
	}

	/* ---------------- Findings filter ---------------- */

	var filterBar = document.querySelector( '.wp2ss-filter' );
	var list = document.querySelector( '.wp2ss-findings' );
	if ( filterBar && list ) {
		var emptyAction = document.querySelector( '.wp2ss-empty-action' );
		var apply = function ( f ) {
			list.setAttribute( 'data-filter', f );
			filterBar.querySelectorAll( '[data-filter]' ).forEach( function ( b ) {
				b.setAttribute( 'aria-pressed', b.getAttribute( 'data-filter' ) === f ? 'true' : 'false' );
			} );
			// Hide groups with nothing to show under this filter.
			list.querySelectorAll( '.wp2ss-group' ).forEach( function ( g ) {
				var any = Array.prototype.some.call( g.querySelectorAll( '.wp2ss-f' ), function ( li ) {
					var s = li.getAttribute( 'data-state' );
					return f === 'all' ? s !== 'ignored' : s === f;
				} );
				g.hidden = ! any;
			} );
			if ( emptyAction ) {
				emptyAction.hidden = f !== 'action' || !! list.querySelector( '.wp2ss-f[data-state="action"]' );
			}
		};
		filterBar.addEventListener( 'click', function ( e ) {
			var b = e.target.closest( '[data-filter]' );
			if ( b ) {
				apply( b.getAttribute( 'data-filter' ) );
			}
		} );
		apply( filterBar.getAttribute( 'data-default' ) || 'all' );
	}

	/* ---------------- Buttons: fix, undo, delete, ignore, copy ---------------- */

	var act = function ( el, action, data ) {
		el.disabled = true;
		var old = el.textContent;
		el.textContent = cfg.i18n.working;
		post( action, data )
			.then( function () {
				window.location.reload();
			} )
			.catch( function ( err ) {
				el.disabled = false;
				el.textContent = old;
				window.alert( err.message );
			} );
	};

	document.addEventListener( 'click', function ( e ) {
		var t = e.target.closest ? e.target.closest( 'button, a' ) : null;
		if ( ! t ) {
			return;
		}
		if ( t.classList.contains( 'wp2ss-fix' ) ) {
			e.preventDefault();
			if ( window.confirm( t.getAttribute( 'data-confirm' ) ) ) {
				act( t, 'wp2ss_fix', { id: t.getAttribute( 'data-id' ) } );
			}
		} else if ( t.classList.contains( 'wp2ss-undo' ) ) {
			e.preventDefault();
			act( t, 'wp2ss_undo', { record: t.getAttribute( 'data-record' ) } );
		} else if ( t.classList.contains( 'wp2ss-purge' ) ) {
			e.preventDefault();
			if ( window.confirm( cfg.i18n.purge ) ) {
				act( t, 'wp2ss_purge', { record: t.getAttribute( 'data-record' ) } );
			}
		} else if ( t.classList.contains( 'wp2ss-toggle' ) ) {
			e.preventDefault();
			act( t, 'wp2ss_ignore', { id: t.getAttribute( 'data-id' ), ignore: t.getAttribute( 'data-ignore' ) === '1' ? 1 : '' } );
		} else if ( t.classList.contains( 'wp2ss-copy' ) ) {
			e.preventDefault();
			var src = document.getElementById( t.getAttribute( 'data-target' ) );
			if ( ! src ) {
				return;
			}
			var done = function () {
				var old = t.textContent;
				t.textContent = cfg.i18n.copied;
				setTimeout( function () {
					t.textContent = old;
				}, 2000 );
			};
			src.select();
			if ( navigator.clipboard && window.isSecureContext ) {
				navigator.clipboard.writeText( src.value ).then( done, function () {
					document.execCommand( 'copy' );
					done();
				} );
			} else {
				document.execCommand( 'copy' );
				done();
			}
		} else if ( t.classList.contains( 'notice-dismiss' ) ) {
			var n = t.closest( '.wp2ss-notice' );
			if ( n ) {
				post( 'wp2ss_dismiss', { report: n.getAttribute( 'data-report' ) } ).catch( function () {} );
			}
		}
	} );

	/* ---------------- Forms that need a confirmation ---------------- */

	document.querySelectorAll( 'form[data-confirm]' ).forEach( function ( f ) {
		f.addEventListener( 'submit', function ( e ) {
			if ( ! window.confirm( f.getAttribute( 'data-confirm' ) ) ) {
				e.preventDefault();
			}
		} );
	} );

	/* ---------------- Fleet: show hub/key fields only for "Report to a hub" ---------------- */

	var fleetForm = document.querySelector( '.wp2ss-fleet-form' );
	if ( fleetForm ) {
		var fields = fleetForm.querySelector( '.wp2ss-member-fields' );
		var sync = function () {
			var checked = fleetForm.querySelector( 'input[name="mode"]:checked' );
			fields.hidden = ! checked || checked.value !== 'member';
		};
		fleetForm.addEventListener( 'change', sync );
		sync();
	}
} )();
