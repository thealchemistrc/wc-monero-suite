( function() {
	'use strict';
	var wc = window.wc || {};
	var wp = window.wp || {};
	var registry = wc.wcBlocksRegistry || window.wcBlocksRegistry;
	var wcSettings = wc.wcSettings || window.wcSettings;
	var htmlEntities = wp.htmlEntities || {};
	var element = wp.element || {};

	if ( ! registry || typeof registry.registerPaymentMethod !== 'function' ) {
		return;
	}
	var getSetting = wcSettings && typeof wcSettings.getSetting === 'function'
		? function( k, d ) { try { return wcSettings.getSetting( k, d ); } catch ( e ) { return d; } }
		: function( k, d ) { return d; };

	var data = getSetting( 'monero_data', {} );
	var decode = typeof htmlEntities.decodeEntities === 'function' ? htmlEntities.decodeEntities : function( s ) { return s; };
	var createEl = typeof element.createElement === 'function' ? element.createElement : function() { return null; };

	var rawTitle = data && typeof data.title === 'string' && data.title ? data.title : 'Monero (XMR)';
	var rawDesc  = data && typeof data.description === 'string' ? data.description : '';
	var label    = decode( rawTitle );
	var desc     = decode( rawDesc );

	try {
		registry.registerPaymentMethod( {
			name: 'monero',
			label: label,
			ariaLabel: label,
			canMakePayment: function() { return true; },
			content: createEl( 'div', { className: 'wc-xmr-blocks-content' }, desc ),
			edit:    createEl( 'div', { className: 'wc-xmr-blocks-edit' }, desc ),
			supports: { features: [ 'products' ] },
		} );
	} catch ( e ) {
		if ( window.console && window.console.error ) {
			window.console.error( '[WC XMR] registerPaymentMethod failed', e );
		}
	}
} )();
