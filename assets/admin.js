/* wp2shell Scanner admin. No dependencies. */
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
		return fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } )
			.then( function ( r ) {
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
		var bar = box.querySelector( '.wp2ss-bar span' );
		var text = box.querySelector( '.wp2ss-progress-text' );
		var cancel = document.getElementById( 'wp2ss-cancel' );
		var stopped = false;
		var failures = 0;

		var show = function ( pct, msg ) {
			box.hidden = false;
			bar.style.width = Math.max( 2, Math.min( 100, pct ) ) + '%';
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

		var begin = function ( force ) {
			stopped = false;
			failures = 0;
			btn.disabled = true;
			show( 1, cfg.i18n.starting );
			post( 'wp2ss_start', force ? { force: 1 } : {} )
				.then( function ( d ) {
					if ( d.done ) {
						window.location.reload();
						return;
					}
					show( d.progress, label( d ) );
					loop();
				} )
				.catch( function ( e ) {
					text.textContent = cfg.i18n.error + ' ' + e.message;
					btn.disabled = false;
				} );
		};

		btn.addEventListener( 'click', function ( e ) {
			e.preventDefault();
			begin( false );
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

	/* ---------------- Ignore / restore ---------------- */

	document.addEventListener( 'click', function ( e ) {
		var t = e.target.closest ? e.target.closest( '.wp2ss-toggle' ) : null;
		if ( ! t ) {
			return;
		}
		e.preventDefault();
		t.disabled = true;
		post( 'wp2ss_ignore', { id: t.getAttribute( 'data-id' ), ignore: t.getAttribute( 'data-ignore' ) === '1' ? 1 : '' } )
			.then( function () {
				window.location.reload();
			} )
			.catch( function ( err ) {
				t.disabled = false;
				window.alert( err.message );
			} );
	} );

	/* ---------------- Dismissible admin notice ---------------- */

	document.addEventListener( 'click', function ( e ) {
		if ( ! e.target.classList || ! e.target.classList.contains( 'notice-dismiss' ) ) {
			return;
		}
		var n = e.target.closest( '.wp2ss-notice' );
		if ( n ) {
			post( 'wp2ss_dismiss', { report: n.getAttribute( 'data-report' ) } ).catch( function () {} );
		}
	} );
} )();
