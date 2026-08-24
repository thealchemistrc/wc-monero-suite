<?php
if ( ! defined( 'ABSPATH' ) ) exit;

use Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType;

class WC_XMR_Blocks extends AbstractPaymentMethodType {
	protected $name = 'monero';

	public function initialize() {
		$raw = get_option( 'woocommerce_monero_settings', array() );
		if ( ! is_array( $raw ) ) {
			error_log( 'WC XMR Blocks: woocommerce_monero_settings option is not an array (' . gettype( $raw ) . ').' );
			$raw = array();
		}
		$this->settings = $raw;
	}

	public function is_active() {
		if ( ! is_array( $this->settings ) ) return false;
		return ( $this->settings['enabled'] ?? 'no' ) === 'yes';
	}

	public function get_payment_method_script_handles() {
		$handle = 'wc-xmr-blocks';
		$src = WC_XMR_PLUGIN_URL . 'blocks.js';
		$ver = file_exists( WC_XMR_PLUGIN_DIR . 'blocks.js' ) ? filemtime( WC_XMR_PLUGIN_DIR . 'blocks.js' ) : '1.0';
		// wp_register_script returns false if already registered - that's fine,
		// the handle is still valid. Only bail if the file doesn't exist at all.
		if ( ! file_exists( WC_XMR_PLUGIN_DIR . 'blocks.js' ) ) {
			error_log( 'WC XMR Blocks: blocks.js missing at ' . WC_XMR_PLUGIN_DIR . 'blocks.js' );
			return array();
		}
		wp_register_script(
			$handle,
			$src,
			array( 'wc-blocks-registry', 'wc-settings', 'wp-element', 'wp-html-entities' ),
			$ver,
			true
		);
		wp_set_script_translations( $handle, 'wc-xmr' );
		return array( $handle );
	}

	public function get_payment_method_data() {
		if ( ! is_array( $this->settings ) ) return array( 'title' => 'Monero (XMR)', 'description' => '', 'supports' => array( 'products' ) );
		return array(
			'title'       => (string) ( $this->settings['title']       ?? 'Monero (XMR)' ),
			'description' => (string) ( $this->settings['description'] ?? '' ),
			'supports'    => array( 'products' ),
		);
	}
}
