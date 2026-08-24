<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WC_Gateway_Monero extends WC_Payment_Gateway {

	protected $addresses_raw;
	protected $reservation_hrs;
	protected $tolerance_pct;
	protected $xmr_price_source;
	protected $manual_rate;
	public $instructions;

	public function __construct() {
		$this->id                 = 'monero';
		$this->method_title       = __( 'Monero (XMR)', 'wc-xmr' );
		$this->method_description = __( 'Accept Monero via a rotating pool of subaddresses. Payments are confirmed manually.', 'wc-xmr' );
		$this->has_fields         = false;
		$this->icon               = '';

		$this->init_form_fields();
		$this->init_settings();

		// Sensitive fields are stored encrypted at rest (if WC_XMR_ENC_KEY is
		// configured) and decrypted here into memory for this request only.
		foreach ( array( 'wallets_json', 'proxy_pass', 'test_wallets_json', 'scanner_view_key' ) as $sensitive_key ) {
			if ( isset( $this->settings[ $sensitive_key ] ) ) {
				$this->settings[ $sensitive_key ] = WC_XMR_Crypto::decrypt( $this->settings[ $sensitive_key ] );
			}
		}

		add_filter( 'woocommerce_settings_api_sanitized_fields_' . $this->id, array( $this, 'encrypt_sensitive_fields' ) );

		$this->title            = $this->get_option( 'title', 'Monero (XMR)' );
		$this->description      = $this->get_option( 'description', 'Pay with Monero. You will be shown a subaddress and amount after placing your order.' );
		$this->addresses_raw    = $this->get_option( 'addresses', '' );
		$this->reservation_hrs  = (float) $this->get_option( 'reservation_hours', 2 );
		$this->tolerance_pct    = (float) $this->get_option( 'tolerance_pct', 3 );
		$this->xmr_price_source = $this->get_option( 'price_source', 'coingecko' );
		$this->manual_rate      = (float) $this->get_option( 'manual_rate', 0 );
		$this->instructions     = $this->get_option( 'instructions', '' );

		add_action( 'woocommerce_update_options_payment_gateways_' . $this->id, array( $this, 'process_admin_options' ) );
		add_action( 'admin_footer', array( $this, 'collapsible_sections_script' ) );
		add_action( 'woocommerce_thankyou_' . $this->id,   array( $this, 'thankyou_page' ) );
		add_action( 'woocommerce_view_order',              array( $this, 'view_order_page' ), 5 );
		add_action( 'woocommerce_email_before_order_table', array( $this, 'email_instructions' ), 10, 3 );
	}

	/**
	 * Runs right before WC_Settings_API::process_admin_options() persists
	 * $this->settings to wp_options. Encrypts the two sensitive fields so
	 * they never hit the DB in plaintext (when WC_XMR_ENC_KEY is set).
	 */
	public function encrypt_sensitive_fields( $settings ) {
		foreach ( array( 'wallets_json', 'proxy_pass', 'test_wallets_json', 'scanner_view_key' ) as $sensitive_key ) {
			if ( isset( $settings[ $sensitive_key ] ) ) {
				$settings[ $sensitive_key ] = WC_XMR_Crypto::encrypt( $settings[ $sensitive_key ] );
			}
		}
		// Normalize the scanner daemon URL at save time too: a scheme-less value
		// ("xmr-node.cakewallet.com:18081") is rejected by WP HTTP with "A valid
		// URL was not provided" and scanner polls silently do nothing. Belt and
		// braces - the scanner class also prepends http:// at runtime.
		if ( isset( $settings['scanner_daemon_url'] ) ) {
			$url = trim( (string) $settings['scanner_daemon_url'] );
			if ( '' !== $url && ! preg_match( '#^https?://#i', $url ) ) {
				$url = 'http://' . $url;
			}
			$settings['scanner_daemon_url'] = rtrim( $url, '/' );
		}
		return $settings;
	}

	/**
	 * Turns each settings section (the h2 + table pairs WooCommerce already
	 * generates from our 'title'-type fields) into a native <details>
	 * accordion. Pure presentation - runs after the form is already in the
	 * DOM, doesn't touch field names/values/validation, so it can't affect
	 * what gets saved. Scoped to only this gateway's own settings screen.
	 * Open/closed state is remembered per-browser via localStorage so it
	 * survives the page reload that happens on save.
	 */
	public function collapsible_sections_script() {
		if ( empty( $_GET['page'] ) || $_GET['page'] !== 'wc-settings' ) return;
		if ( empty( $_GET['section'] ) || $_GET['section'] !== $this->id ) return;
		?>
		<style>
			.wc-xmr-acc { border: 1px solid #dcdcde; border-radius: 4px; margin: 0 0 12px; background: #fff; }
			.wc-xmr-acc > summary {
				list-style: none; cursor: pointer; padding: 10px 14px; font-weight: 600; font-size: 14px;
				background: #f6f7f7; border-radius: 4px; user-select: none;
			}
			.wc-xmr-acc > summary::-webkit-details-marker { display: none; }
			.wc-xmr-acc > summary::before { content: ''; display: inline-block; margin-right: 8px; font-size: 10px; transition: transform 0.15s ease; }
			.wc-xmr-acc[open] > summary::before { transform: rotate(90deg); }
			.wc-xmr-acc[open] > summary { border-bottom: 1px solid #dcdcde; border-radius: 4px 4px 0 0; }
			.wc-xmr-acc table.form-table { margin-top: 0; }
		</style>
		<script>
		(function(){
			document.addEventListener('DOMContentLoaded', function(){
				var form = document.querySelector('#mainform');
				if (!form) return;
				var headings = Array.prototype.slice.call(form.querySelectorAll('h2'));
				if (!headings.length) return;

				headings.forEach(function(h2, idx){
					var table = h2.nextElementSibling;
					if (!table || table.tagName !== 'TABLE') return;

					var key = 'wc_xmr_acc_' + idx;
					var stored = window.localStorage.getItem(key);
					// Default open on first visit so nothing is hidden the
					// first time someone lands here; remembers their choice
					// (open/closed) on every visit after that.
					var isOpen = stored === null ? true : stored === '1';

					var details = document.createElement('details');
					details.className = 'wc-xmr-acc';
					if (isOpen) details.setAttribute('open', '');

					var summary = document.createElement('summary');
					summary.textContent = h2.textContent.replace(/^-\s*|\s*-$/g, '').trim();

					h2.parentNode.insertBefore(details, h2);
					details.appendChild(summary);
					details.appendChild(table);
					h2.remove();

					details.addEventListener('toggle', function(){
						window.localStorage.setItem(key, details.open ? '1' : '0');
					});
				});
			});
		})();
		</script>
		<?php
	}

	/**
	 * Custom settings field type: renders a read-only summary of the
	 * addresses currently pushed from the Monero Push Companion plugin.
	 *
	 * WooCommerce payment-gateway settings don't support a generic
	 * info/custom field out of the box - title-type fields only render
	 * their heading, never a description - so we register a custom type
	 * with this matching generate_<type>_html() method. Displays a row in
	 * the Address mode section showing what a paired remote device has
	 * sent over for each network.
	 */
	public function generate_push_pool_info_html( $key, $data ) {
		$field_key = $this->get_field_key( $key );
		$defaults  = array( 'title' => '', 'class' => '' );
		$data      = wp_parse_args( $data, $defaults );
		return '<tr valign="top">' .
			'<th scope="row" class="titledesc">' .
				'<label for="' . esc_attr( $field_key ) . '">' . esc_html( $data['title'] ) . '</label>' .
			'</th>' .
			'<td class="forminp forminp-' . esc_attr( sanitize_title( $data['type'] ) ) . '">' .
				$this->push_pool_summary() .
			'</td>' .
		'</tr>';
	}

	/**
	 * HTML summary of the addresses currently pushed from the Monero Push
	 * Companion plugin (stored by that plugin under wc_xmr_push_{network}_addresses).
	 * Displayed on this gateway's settings page so the operator can see at
	 * a glance what a paired remote device has sent over, without needing
	 * to open the push plugin's own screen. Returns a friendly note when
	 * nothing has been pushed yet or the option can't be read.
	 */
	private function push_pool_summary() {
		$lines = array();
		$networks = array(
			'mainnet' => 'Mainnet',
			'testnet' => 'Testnet/Stagenet',
		);
		foreach ( $networks as $net => $label ) {
			$key = 'wc_xmr_push_' . $net . '_addresses';
			try {
				$pushed = get_option( $key, array() );
			} catch ( Throwable $e ) {
				error_log( 'WC XMR: get_option ' . $key . ' threw in push_pool_summary: ' . $e->getMessage() );
				$pushed = array();
			}
			if ( ! is_array( $pushed ) ) $pushed = array();
			if ( empty( $pushed ) ) {
				$lines[] = '<strong>' . $label . ':</strong> no addresses pushed yet.';
				continue;
			}
			$count = count( $pushed );
			$shown = array_slice( $pushed, 0, 5 );
			$items = array();
			foreach ( $shown as $entry ) {
				$addr = is_array( $entry ) ? ( $entry['address'] ?? '' ) : (string) $entry;
				if ( $addr === '' ) continue;
				$suffix = ( is_array( $entry ) && isset( $entry['exact_amount'] ) ) ? ' <em>(exact-amount entry)</em>' : '';
				$items[] = '<code style="font-family:monospace;">' . esc_html( $addr ) . '</code>' . $suffix;
			}
			$lines[] = '<strong>' . $label . ':</strong> ' . $count . ' address(es) pushed.'
				. ( $items ? '<br>' . implode( '<br>', $items ) : '' )
				. ( $count > count( $shown ) ? '<br><em>...and ' . ( $count - count( $shown ) ) . ' more.</em>' : '' );
		}
		return implode( '<br>', $lines )
			. '<br><em>Addresses are injected into the manual pool via the <code>wc_xmr_manual_address_pool</code> filter. Pushed addresses are served when the Address source (or the Fallback address source) is set to "Push plugin".</em>';
	}

	public function init_form_fields() {
		$this->form_fields = array(
			'enabled' => array(
				'title'   => 'Enable/Disable', 'type' => 'checkbox',
				'label'   => 'Enable Monero payments', 'default' => 'no',
			),
			'title' => array( 'title' => 'Title', 'type' => 'text', 'default' => 'Monero (XMR)' ),
			'description' => array( 'title' => 'Description', 'type' => 'textarea',
				'default' => 'Pay with Monero. Address shown after checkout.' ),
			'instructions' => array( 'title' => 'Instructions (thank-you page & email)', 'type' => 'textarea',
				'default' => 'Send the exact amount below. Order dispatched once payment confirmed on-chain.' ),

			'mode_section' => array( 'title' => '- Address mode -', 'type' => 'title' ),
			'address_mode' => array(
				'title' => 'Address source', 'type' => 'select',
				'options' => array(
					'manual'  => 'Manual paste (no RPC needed)',
					'auto'    => 'Auto-generate from wallet RPC',
					'hybrid'  => 'Hybrid: auto if RPC up, fall back to manual pool',
					'scanner' => 'Scanner (view-only, no wallet-rpc) LEAST SECURE',
					'push'    => 'Push plugin (addresses pushed from a remote device)',
				),
				'default' => 'manual',
				'description' => '"Push plugin" uses only addresses pushed from a paired remote device running xmr-pushd (via the Monero Push Companion plugin). Requires the push plugin to be installed and at least one address batch pushed for the current network.',
			),
			'address_failover' => array(
				'title' => 'Fallback address source (optional redundancy)', 'type' => 'select',
				'options' => array(
					'off'     => 'Off - single source only (no fallback)',
					'manual'  => 'Manual paste (no RPC needed)',
					'auto'    => 'Auto-generate from wallet RPC',
					'hybrid'  => 'Hybrid: auto if RPC up, fall back to manual pool',
					'scanner' => 'Scanner (view-only, no wallet-rpc) LEAST SECURE',
					'push'    => 'Push plugin (addresses pushed from a remote device)',
				),
				'default' => 'off',
				'description' => 'Optional. If the primary Address source above fails to produce an address for a checkout (e.g. wallet-rpc down, scanner misconfigured, push plugin unreachable), the plugin automatically tries this backup source and emails you an admin alert so you know the primary is having trouble. Must be different from the primary source to take effect. Leave Off for a single source with no redundancy.',
			),
			'addresses' => array(
				'title' => 'Manual address pool (one per line)', 'type' => 'textarea',
				'description' => 'Used in manual + hybrid modes. Only mainnet subaddresses (start with 8).',
				'css' => 'height:180px;font-family:monospace;', 'default' => '',
			),
			'push_pool_info' => array(
				'title' => 'Pushed address pool (from Monero Push Companion)',
				'type' => 'push_pool_info',
			),

			'wallet_section' => array( 'title' => '- Wallets (RPC) -', 'type' => 'title',
				'description' => 'Configure one or more monero-wallet-rpc endpoints for auto-detection. Multiple wallets = better opsec + rotation. If wallet-rpc feels unreliable on Windows specifically (random disconnects, needing frequent restarts), that\'s a very common, well-known pain point - it\'s Linux-first software, and Windows has recurring issues with wallet-file locking, path handling, and antivirus interference around it. Running it inside WSL2 or a small Linux VM/VPS instead (even alongside a Windows desktop) tends to fix it outright - this plugin now retries transient failures automatically and gives clearer error messages either way, but that\'s resilience, not a substitute for a more stable host for wallet-rpc itself.' ),
			'wallets_json' => array(
				'title' => 'Wallets (JSON array)', 'type' => 'textarea',
				'css' => 'height:200px;font-family:monospace;',
				'description' => 'Example:<br><code>[{"id":"main","label":"Main","url":"https://rpc.example.com:18083/json_rpc","user":"foo","pass":"bar","account":0,"weight":1}]</code><br>Weight controls rotation frequency. Leave empty to disable RPC.',
				'default' => '',
			),
			'onion_gateway' => array(
				'title' => 'Tor2web gateway (for .onion wallet URLs)', 'type' => 'text',
				'description' => 'Only needed if a wallet URL above is a .onion address - this ordinary web host has no Tor client of its own, so requests get routed through a public tor2web gateway instead. Enter just the gateway suffix, e.g. <code>onion.pet</code> (a .onion URL like <code>abc...xyz.onion</code> becomes <code>https://abc...xyz.onion.pet/json_rpc</code>). Leave blank if this host already has direct Tor access (e.g. a local SOCKS proxy), or if no wallet URL is an onion address. Public gateways come and go - verify the one you pick is still active, and swap this value if it stops working. Note: unless the onion service itself also serves HTTPS end-to-end, the gateway operator can see the RPC traffic content (though not your login credentials, since digest auth never sends the password itself) - acceptable for a view-only wallet, worth knowing regardless.',
				'default' => '',
			),
			'wallet_rotation' => array(
				'title' => 'Wallet rotation', 'type' => 'select',
				'options' => array(
					'round_robin' => 'Round-robin (weighted)',
					'random'      => 'Random (weighted)',
					'least_used'  => 'Least recently used',
				),
				'default' => 'round_robin',
			),
			'lookahead_warn' => array(
				'title' => 'Warn when subaddress index within N of lookahead', 'type' => 'number',
				'default' => '20', 'custom_attributes' => array( 'min' => '5' ),
				'description' => 'Emails admin when a wallet approaches its subaddress lookahead limit so you can bump it.',
			),

			'scanner_section' => array( 'title' => '- Scanner (view-only, pure PHP, no wallet-rpc) LEAST SECURE -', 'type' => 'title',
				'description' => 'The scanner uses a view-only wallet (primary address + private view key) to scan the blockchain directly via a monerod JSON-RPC node - no monero-wallet-rpc or Node.js sidecar needed. LEAST SECURE: the private view key is held in PHP process memory. If the server is compromised, the view key can be extracted, revealing all incoming transactions. MAY AFFECT SERVER PERFORMANCE: scanning fetches full blocks from a daemon and runs ed25519 + Keccak in pure PHP (GMP/BCMath). CPU/memory intensive. NOT recommended for production stores on shared hosting. Only used when Address source is set to "Scanner". Powered by <a href="https://github.com/SlowBearDigger/xmr-pay" target="_blank" rel="noopener noreferrer">xmr-pay</a> (SlowBearDigger).' ),
			'scanner_daemon_url' => array(
				'title' => 'Monero daemon URL', 'type' => 'text',
				'default' => 'http://127.0.0.1:18081',
				'description' => 'URL of a monerod JSON-RPC endpoint (e.g. <code>http://127.0.0.1:18081</code> for a local node, or a trusted remote node like <code>xmr-node.cakewallet.com:18081</code>). Include <code>http://</code>/<code>https://</code>; a bare host:port is accepted and http:// is added automatically. Must have <code>--rpc-bind-ip</code> and <code>--rpc-restricted-bind-port</code> or <code>--rpc-bind-port</code> configured. A full (non-pruned) node is required for commitment verification.',
			),
			'scanner_primary_address' => array(
				'title' => 'Primary Monero address', 'type' => 'text',
				'description' => 'The primary address of your view-only wallet. Subaddresses are derived from this + the view key for each order. Do NOT use a subaddress here - it must be the primary (account 0, index 0) address.',
				'css' => 'font-family:monospace;',
			),
			'scanner_view_key' => array(
				'title' => 'Private view key', 'type' => 'password',
				'description' => 'The private view key for the primary address above. Stored encrypted at rest (if WC_XMR_ENC_KEY is configured). LEAST SECURE: this key is loaded into PHP process memory during scanning.',
				'css' => 'font-family:monospace;',
			),
			'scanner_log_level' => array(
				'title' => 'Scanner log level', 'type' => 'select',
				'options' => array(
					'1' => 'ERROR only (critical failures)',
					'2' => 'WARN (recoverable errors, degraded operation)',
					'3' => 'INFO (normal operation: scans, matches, confirmations)',
					'4' => 'DEBUG (verbose: every RPC call, every output checked)',
				),
				'default' => '3',
				'description' => 'Controls how much the native scanner logs. DEBUG is very verbose - only use for troubleshooting.',
			),
			'scanner_restore_height' => array(
				'title' => 'Scanner restore height', 'type' => 'number',
				'default' => '0', 'custom_attributes' => array( 'min' => '0' ),
				'description' => 'Block height to start scanning from. 0 = scan from the current daemon tip (only new blocks). Set higher to skip old blocks. Lower = more thorough but slower.',
			),

			'conf_section' => array( 'title' => '- Confirmations -', 'type' => 'title' ),
			'conf_processing' => array(
				'title' => 'Confirmations for "Processing"', 'type' => 'number',
				'default' => '1', 'custom_attributes' => array( 'min' => '0', 'max' => '100' ),
				'description' => 'When received tx reaches this many confs, order → Processing.',
			),
			'conf_complete' => array(
				'title' => 'Confirmations for "Complete" (0 = never auto-complete)', 'type' => 'number',
				'default' => '10', 'custom_attributes' => array( 'min' => '0', 'max' => '100' ),
				'description' => 'Set 0 to stay in Processing forever for manual review.',
			),
			'poll_interval' => array(
				'title' => 'Poll interval (minutes)', 'type' => 'number',
				'default' => '5', 'custom_attributes' => array( 'min' => '2', 'max' => '60' ),
				'description' => 'How often to check RPC for new payments. Min 2 to stay light on shared hosting. The customer-facing progress bar\'s refresh rate scales with this automatically - no separate setting needed there.',
			),

			'price_section' => array( 'title' => '- Pricing -', 'type' => 'title' ),
			'price_source' => array(
				'title' => 'Price source', 'type' => 'select',
				'options' => array(
					'coingecko'  => 'CoinGecko (fallback: Kraken)',
					'kraken'     => 'Kraken (fallback: CoinGecko)',
					'manual'     => 'Manual fixed rate',
				),
				'default' => 'coingecko',
			),
			'manual_rate' => array(
				'title' => 'Manual rate (1 XMR = ? fiat)', 'type' => 'number',
				'default' => '0', 'custom_attributes' => array( 'step' => '0.00000001' ),
			),
			'price_fallback_url' => array(
				'title' => 'Fallback price URL (used only if CoinGecko + Kraken both fail)', 'type' => 'text',
				'description' => 'Optional. CoinGecko and Kraken both sit behind anti-bot protection that commonly 403s Tor exit IPs - if you\'re proxying this plugin\'s traffic over Tor (see Privacy/Proxy section below), price lookups can fail even though wallet-rpc works fine. Point this at a JSON endpoint you trust and have verified yourself (e.g. a small price relay you self-host, or an onion mirror you\'ve personally confirmed is genuine - we deliberately do not ship a hardcoded third-party .onion address here, since a wrong or stale one is worse than none). Use <code>{currency}</code> as a placeholder, e.g. <code>http://yourown7onionaddresshere.onion/price?cur={currency}</code>. Leave blank to disable.',
			),
			'price_fallback_json_path' => array(
				'title' => 'Fallback response JSON path', 'type' => 'text',
				'default' => 'monero.{currency}',
				'description' => 'Dot-notation path to the numeric price inside the fallback endpoint\'s JSON response. Default matches a CoinGecko-shaped response (<code>{"monero":{"usd":123.45}}</code>). For a flat <code>{"price":123.45}</code> response, use <code>price</code>. <code>{currency}</code> is replaced automatically.',
			),
			'rate_stale_warn' => array(
				'title' => 'Warn customer if quote older than N minutes', 'type' => 'number',
				'default' => '30', 'custom_attributes' => array( 'min' => '5' ),
			),
			'tolerance_pct' => array(
				'title' => 'Silent underpayment tolerance (%)', 'type' => 'number',
				'default' => '3', 'custom_attributes' => array( 'min' => '0', 'max' => '20', 'step' => '0.1' ),
			),
			'amount_nonce' => array(
				'title' => 'Add unique piconero nonce to each quote', 'type' => 'checkbox',
				'label' => 'Enable (helps distinguish txs when addresses reused)', 'default' => 'yes',
			),

			'reservation_hours' => array(
				'title' => 'Reservation lifetime (hours)', 'type' => 'number',
				'default' => '2', 'custom_attributes' => array( 'min' => '0.25', 'step' => '0.25' ),
			),

			'rl_section' => array( 'title' => '- Rate limiting -', 'type' => 'title',
				'description' => 'Combines a behavioral score per IP+user-agent fingerprint (rewarding spaced-out, distinct-cart requests; penalizing rapid repeats of the same cart) with a flat per-IP hourly cap and a global pool-exhaustion guard below.' ),
			'trust_cf_ip' => array(
				'title' => 'Behind Cloudflare?', 'type' => 'checkbox',
				'label' => 'Trust the CF-Connecting-IP header for rate limiting', 'default' => 'no',
				'description' => 'Only enable this if your site actually sits behind Cloudflare. When enabled, the real client IP is taken from CF-Connecting-IP - but ONLY when the request\'s actual REMOTE_ADDR is a genuine Cloudflare edge IP (checked against Cloudflare\'s published ranges), not just because the header is present. If this is off (default) or your site isn\'t behind Cloudflare, leaving it off is safer - otherwise anyone who can reach your origin directly can forge this header to spoof any IP and bypass all rate limiting.',
			),
			'rl_max_per_hour' => array(
				'title' => 'Max XMR checkouts per IP per hour (coarse floor)', 'type' => 'number',
				'default' => '5', 'custom_attributes' => array( 'min' => '1' ),
			),
			'rl_max_concurrent' => array(
				'title' => 'Baseline max concurrent unpaid reservations per IP', 'type' => 'number',
				'default' => '2', 'custom_attributes' => array( 'min' => '1' ),
				'description' => 'This is the baseline for a clean-behavior fingerprint. It shrinks automatically as a fingerprint\'s behavior score rises - a low-scoring genuine shopper still gets the full amount.',
			),
			'rl_score_throttle' => array(
				'title' => 'Behavior score: soft-throttle threshold', 'type' => 'number',
				'default' => '40', 'custom_attributes' => array( 'min' => '1', 'max' => '99', 'step' => '1' ),
				'description' => 'Above this score, a fingerprint must wait a bit longer between address requests (gap grows with score) instead of being blocked outright.',
			),
			'rl_score_block' => array(
				'title' => 'Behavior score: hard-block threshold', 'type' => 'number',
				'default' => '80', 'custom_attributes' => array( 'min' => '1', 'max' => '100', 'step' => '1' ),
				'description' => 'Above this score, the fingerprint is temporarily blocked (duration below, scaled up slightly the further over threshold it is).',
			),
			'rl_score_decay_min' => array(
				'title' => 'Behavior score half-life (minutes)', 'type' => 'number',
				'default' => '15', 'custom_attributes' => array( 'min' => '1' ),
				'description' => 'How quickly a quiet fingerprint\'s score fades back to zero. Shorter = more forgiving of past bursts; longer = remembers bad behavior longer.',
			),
			'rl_block_minutes' => array(
				'title' => 'Block duration on limit hit (minutes)', 'type' => 'number',
				'default' => '10', 'custom_attributes' => array( 'min' => '1' ),
			),
			'rl_alt_message' => array(
				'title' => 'Message when rate-limited', 'type' => 'text',
				'default' => 'Too many Monero orders from your connection. Please use BTCPay or wait 10 minutes.',
			),
			'rl_max_pool_pct' => array(
				'title' => 'Max % of manual address pool reservable at once (global)', 'type' => 'number',
				'default' => '80', 'custom_attributes' => array( 'min' => '10', 'max' => '100' ),
				'description' => 'Applies site-wide, regardless of which IP is checking out - a per-IP limit alone does nothing against an attacker spreading requests across many IPs/proxies to exhaust your address pool as a denial-of-service. When the manual pool hits this percentage of concurrent reservations, new manual-pool checkouts are declined with the rate-limit message above until reservations expire or are paid. Only applies to the manual address pool (auto/RPC mode isn\'t pool-limited the same way).',
			),
			'poller_batch_limit' => array(
				'title' => 'Poller batch limit (orders checked per 5-min cycle)', 'type' => 'number',
				'default' => '200', 'custom_attributes' => array( 'min' => '10' ),
				'description' => 'If you routinely have more than this many pending XMR orders at once, raise it - orders beyond the limit wait for the next cycle rather than being skipped entirely, and you\'ll get an admin alert when the batch fills up.',
			),

			'test_section' => array( 'title' => '- Test mode -', 'type' => 'title',
				'description' => 'Two flavors. "Simulate" makes zero real network calls and gives cheat buttons on each order to instantly jump to any payment state - fastest way to test flow/UI/emails. "Testnet" runs the real code path unchanged (real address generation, real wallet-rpc polling) against a wallet-rpc you point at Monero testnet/stagenet. Either mode refuses to activate on anything WordPress detects as a production environment unless you explicitly override that below - this is a real safety check (WP_ENVIRONMENT_TYPE), not just a label.' ),
			'test_mode' => array(
				'title' => 'Test mode', 'type' => 'select',
				'options' => array(
					'off'      => 'Off (real payments)',
					'simulate' => 'Simulate (no real network calls, cheat buttons)',
					'testnet'  => 'Testnet (real flow, testnet wallet-rpc)',
				),
				'default' => 'off',
			),
			'test_mode_env_override' => array(
				'title' => 'Production environment override', 'type' => 'checkbox',
				'label' => 'I understand this looks like a production environment and want test mode anyway', 'default' => 'no',
				'description' => 'Only needed if WordPress reports this site as a production environment (the default when WP_ENVIRONMENT_TYPE isn\'t set in wp-config.php) and you still want test mode here. Prefer setting WP_ENVIRONMENT_TYPE to "staging"/"local" on your actual test site instead of using this.',
			),
			'test_max_order_total' => array(
				'title' => 'Test mode order-total safety ceiling', 'type' => 'number',
				'default' => '50', 'custom_attributes' => array( 'min' => '1' ),
				'description' => 'Orders above this total are refused while test mode is active - a safety valve against a real large order accidentally going through the test flow (simulated or testnet).',
			),
			'test_wallets_json' => array(
				'title' => 'Testnet wallet-rpc config', 'type' => 'textarea',
				'description' => 'Same JSON array format as the real "Wallet-rpc endpoints" field above, but pointed at wallet-rpc running against Monero testnet/stagenet. Only used when test mode is set to "Testnet" - completely separate from your production wallet config, so there\'s no risk of mixing them up.',
				'css' => 'height:100px;',
			),
			'test_addresses' => array(
				'title' => 'Testnet manual address pool', 'type' => 'textarea',
				'description' => 'Separate from the real "Manual address pool" above - used instead of it when test mode is "Testnet" and address mode is manual/hybrid. This prevents testnet mode from ever handing out your real mainnet addresses. Note: address validation here is deliberately loose (charset/length only, not a strict network-prefix check, since testnet/stagenet use different prefix bytes than mainnet) - for full correctness, prefer address mode "Auto" or "Hybrid" for testnet so addresses come straight from your testnet wallet-rpc instead of a hand-pasted pool.',
				'css' => 'height:100px;',
			),
			'explorer_url' => array(
				'title' => 'Block explorer link(s) (mainnet)', 'type' => 'textarea',
				'description' => 'Optional, one URL template per line - if you list more than one, all are shown as separate links so a single dead explorer doesn\'t leave you with nothing (same reasoning as the price-source fallback chain above). Use <code>{txid}</code> as a placeholder. Example: <code>https://xmrchain.net/tx/{txid}</code> on one line, <code>https://moneroblocks.info/tx/{txid}</code> on the next. Left blank by default - nothing is hardcoded here, pick sources you trust.',
				'css' => 'height:70px;',
			),
			'test_explorer_url' => array(
				'title' => 'Block explorer link(s) (testnet)', 'type' => 'textarea',
				'description' => 'Same format as above (one URL template per line), used instead whenever test mode is "Testnet". Public testnet/stagenet explorers are rare and often unreliable single-maintainer instances - for anything you actually depend on, self-host onion-monero-blockchain-explorer with its <code>--testnet</code> flag against your own testnet node, and list that here.',
				'css' => 'height:70px;',
			),

			'proxy_section' => array( 'title' => '- Privacy / Proxy -', 'type' => 'title',
				'description' => 'Route this plugin\'s own outbound calls (wallet-rpc + XMR price lookups) through a proxy, so your server\'s IP is never seen connecting directly to your wallet node or price APIs. This ONLY affects this plugin\'s traffic - nothing else on the site is rerouted.' ),
			'proxy_enabled' => array(
				'title' => 'Enable proxy for wallet-rpc + price calls', 'type' => 'checkbox',
				'label' => 'Enable', 'default' => 'no',
			),
			'proxy_type' => array(
				'title' => 'Proxy type', 'type' => 'select',
				'options' => array(
					'socks5h' => 'SOCKS5h (resolves hostnames via the proxy - recommended, no DNS leak)',
					'socks5'  => 'SOCKS5 (resolves hostnames locally - can leak DNS)',
					'http'    => 'HTTP/HTTPS proxy',
				),
				'default' => 'socks5h',
				'description' => 'Mullvad\'s SOCKS5 proxy (and most VPN SOCKS5 proxies) should use socks5h so your server\'s own DNS resolver never sees the wallet-rpc or price-API hostnames.',
			),
			'proxy_host' => array( 'title' => 'Proxy host', 'type' => 'text',
				'description' => 'e.g. Mullvad SOCKS5 relay hostname/IP.' ),
			'proxy_port' => array( 'title' => 'Proxy port', 'type' => 'number', 'default' => '1080' ),
			'proxy_user' => array( 'title' => 'Proxy username (optional)', 'type' => 'text' ),
			'proxy_pass' => array( 'title' => 'Proxy password (optional)', 'type' => 'password' ),

			'alerts_section' => array( 'title' => '- Alerts -', 'type' => 'title' ),
			'alert_email' => array(
				'title' => 'Alert email (blank = admin email)', 'type' => 'email', 'default' => '',
			),
			'pool_low_pct' => array(
				'title' => 'Warn when free addresses below (%)', 'type' => 'number',
				'default' => '20', 'custom_attributes' => array( 'min' => '5', 'max' => '90' ),
			),
		);
	}

	/* --------------------------- XMR price --------------------------- */

	/* --------------------------- Process payment --------------------------- */

	public function process_payment( $order_id ) {
		global $wpdb;
		try {
			$order_id = (int) $order_id;
			if ( $order_id <= 0 ) { error_log( 'WC XMR: process_payment got invalid order_id: ' . var_export( func_get_arg( 0 ), true ) ); return array( 'result' => 'failure' ); }
			$table = $wpdb->prefix . 'wc_xmr_reservations';
			if ( empty( $table ) ) { error_log( 'WC XMR: process_payment got empty table prefix.' ); return array( 'result' => 'failure' ); }
			try { $order = wc_get_order( $order_id ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_get_order threw in process_payment for #' . $order_id . ': ' . $e->getMessage() ); return array( 'result' => 'failure' ); }
			if ( ! $order ) { error_log( 'WC XMR: process_payment - order #' . $order_id . ' not found.' ); return array( 'result' => 'failure' ); }

			try { $ip_hash = wc_xmr_ip_hash(); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_ip_hash threw: ' . $e->getMessage() ); $ip_hash = hash( 'sha256', '0.0.0.0|' . wp_salt() ); }
			try { $rl = wc_xmr_check_rate_limit( $order, $ip_hash, $this->settings ); } catch ( Throwable $e ) { error_log( 'WC XMR: check_rate_limit threw for #' . $order_id . ': ' . $e->getMessage() ); $rl = true; }
			if ( $rl !== true ) {
				wc_add_notice( is_string( $rl ) ? $rl : 'Rate limited.', 'error' );
				return array( 'result' => 'failure' );
			}

			try {
				$existing = $wpdb->get_row( $wpdb->prepare(
					"SELECT * FROM {$table} WHERE order_id = %d AND status IN ('reserved','detected')", $order_id
				) );
				if ( $wpdb->last_error ) { error_log( 'WC XMR: existing reservation lookup failed for #' . $order_id . ': ' . $wpdb->last_error ); $existing = null; }
			} catch ( Throwable $e ) { error_log( 'WC XMR: existing lookup threw for #' . $order_id . ': ' . $e->getMessage() ); $existing = null; }

		$test_mode = wc_xmr_test_mode();
		if ( $test_mode === 'simulate' && ! $existing ) {
			$ceiling = (float) $this->get_option( 'test_max_order_total', 50 );
			if ( (float) $order->get_total() > $ceiling ) {
				wc_add_notice( sprintf( 'Test mode is active and this order total exceeds the configured test ceiling (%s). Lower the order total or raise the ceiling in test mode settings.', wc_price( $ceiling ) ), 'error' );
				return array( 'result' => 'failure' );
			}

			$address = wc_xmr_simulate_fake_address( $order_id );
			// A believable-but-fake rate so the simulated amount looks realistic
			// even if real price sources are also being tested/unavailable.
			$rate = wc_xmr_get_rate( $order->get_currency(), $this->settings );
			if ( $rate <= 0 ) $rate = 150;
			$amount     = round( (float) $order->get_total() / $rate, 12 );
			$min_amount = round( $amount * ( 1 - ( (float) $this->get_option( 'tolerance_pct', 3 ) / 100 ) ), 12 );
			$now        = current_time( 'mysql', 1 );
			$expires    = gmdate( 'Y-m-d H:i:s', time() + (int) ( (float) $this->get_option( 'reservation_hours', 2 ) * 3600 ) );

			$inserted = $wpdb->insert( $table, array(
				'address' => $address, 'order_id' => $order_id,
				'wallet_id' => '__test_simulate__', 'account_index' => 0, 'subaddress_index' => 0,
				'amount_xmr' => $amount, 'min_amount_xmr' => $min_amount,
				'reserved_at' => $now, 'expires_at' => $expires,
				'status' => 'reserved', 'ip_hash' => $ip_hash,
			) );
			if ( $inserted === false ) {
				error_log( sprintf( 'WC XMR: Failed to insert reservation for order #%d (simulate): %s', $order_id, $wpdb->last_error ) );
				wc_add_notice( 'Failed to create reservation record. Please try again.', 'error' );
				return array( 'result' => 'failure' );
			}

			$order->update_meta_data( '_xmr_address', $address );
			$order->update_meta_data( '_xmr_amount', $amount );
			$order->update_meta_data( '_xmr_min_amount', $min_amount );
			$order->update_meta_data( '_xmr_rate', $rate );
			$order->update_meta_data( '_xmr_rate_locked_at', time() );
			$order->update_meta_data( '_xmr_expires_at', $expires );
			$order->update_meta_data( '_xmr_wallet_id', '__test_simulate__' );
			$order->save();

			$order->update_status( 'on-hold', '[TEST MODE] Awaiting simulated Monero payment - use the "Simulate Payment" box on this order to fast-forward.' );
			wc_reduce_stock_levels( $order_id );
			WC()->cart->empty_cart();
			return array( 'result' => 'success', 'redirect' => $this->get_return_url( $order ) );
		}

		if ( $existing ) {
			$address = $existing->address;
			$amount  = (float) $existing->amount_xmr;
		} else {
			if ( $test_mode === 'testnet' ) {
				$ceiling = (float) $this->get_option( 'test_max_order_total', 50 );
				if ( (float) $order->get_total() > $ceiling ) {
					wc_add_notice( sprintf( 'Test mode (testnet) is active and this order total exceeds the configured test ceiling (%s). This is a safety valve to stop a real large order accidentally going through the testnet flow.', wc_price( $ceiling ) ), 'error' );
					return array( 'result' => 'failure' );
				}
			}

			// Pick wallet + address per configured mode
			$picked = wc_xmr_pick_address( $this->settings );
			if ( is_wp_error( $picked ) ) {
				wc_add_notice( $picked->get_error_message(), 'error' );
				return array( 'result' => 'failure' );
			}
			$address     = $picked['address'];
			$wallet_id   = $picked['wallet_id'];
			$acct        = $picked['account_index'];
			$sub_idx     = $picked['subaddress_index'];

			$currency = $order->get_currency();
			$rate     = wc_xmr_get_rate( $currency, $this->settings );
			if ( $rate <= 0 ) {
				wc_add_notice( 'Unable to fetch Monero exchange rate. Try again shortly.', 'error' );
				return array( 'result' => 'failure' );
			}

			$total_fiat = (float) $order->get_total();
			$amount     = $total_fiat / $rate;

			// Add tiny nonce for uniqueness
			if ( $this->get_option( 'amount_nonce' ) === 'yes' ) {
				$nonce = mt_rand( 1, 9999 ) / 1e12; // up to ~0.00000001 XMR
				$amount += $nonce;
			}
			$amount = round( $amount, 12 );
			$min_amount = round( $amount * ( 1 - ( (float) $this->get_option( 'tolerance_pct', 3 ) / 100 ) ), 12 );

			$now     = current_time( 'mysql', 1 );
			$expires = gmdate( 'Y-m-d H:i:s', time() + (int) ( (float) $this->get_option( 'reservation_hours', 2 ) * 3600 ) );

			// Per-order scan checkpoint: we do NOT fetch the daemon tip here
			// because a synchronous RPC call during checkout blocks the
			// customer's browser if the daemon is slow or unreachable.
			// checkout_height stays 0 at insert time; the poller's first
			// cycle for this order will discover the current tip and set
			// the checkpoint then (falling back to scanner_restore_height
			// for legacy orders that still have checkout_height=0).
			$checkout_height = 0;

			$inserted = $wpdb->insert( $table, array(
				'address' => $address, 'order_id' => $order_id,
				'wallet_id' => $wallet_id, 'account_index' => $acct, 'subaddress_index' => $sub_idx,
				'amount_xmr' => $amount, 'min_amount_xmr' => $min_amount,
				'reserved_at' => $now, 'expires_at' => $expires,
				'status' => 'reserved', 'ip_hash' => $ip_hash,
				'checkout_height' => $checkout_height,
			) );
			if ( $inserted === false ) {
				error_log( sprintf( 'WC XMR: Failed to insert reservation for order #%d: %s', $order_id, $wpdb->last_error ) );
				wc_add_notice( 'Failed to reserve payment address. Please try again.', 'error' );
				return array( 'result' => 'failure' );
			}

			$order->update_meta_data( '_xmr_address', $address );
			$order->update_meta_data( '_xmr_amount', $amount );
			$order->update_meta_data( '_xmr_min_amount', $min_amount );
			$order->update_meta_data( '_xmr_rate', $rate );
			$order->update_meta_data( '_xmr_rate_locked_at', time() );
			$order->update_meta_data( '_xmr_expires_at', $expires );
			$order->update_meta_data( '_xmr_wallet_id', $wallet_id );
			$order->update_meta_data( '_xmr_account_index', $acct );
			$order->update_meta_data( '_xmr_subaddress_index', $sub_idx );
			$order->save();
		}

		try { $order->update_status( 'on-hold', 'Awaiting Monero payment.' ); } catch ( Throwable $e ) { error_log( 'WC XMR: update_status on-hold threw for #' . $order_id . ': ' . $e->getMessage() ); }
		try { $order->add_order_note( sprintf( 'XMR requested: %s to %s (min: %s)', $amount, $address, $order->get_meta( '_xmr_min_amount' ) ) ); } catch ( Throwable $e ) { error_log( 'WC XMR: add_order_note threw for #' . $order_id . ': ' . $e->getMessage() ); }

		try { wc_reduce_stock_levels( $order_id ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_reduce_stock_levels threw for #' . $order_id . ': ' . $e->getMessage() ); }
		try { if ( WC()->cart ) WC()->cart->empty_cart(); } catch ( Throwable $e ) { error_log( 'WC XMR: empty_cart threw: ' . $e->getMessage() ); }

		try { $redirect = $this->get_return_url( $order ); } catch ( Throwable $e ) { error_log( 'WC XMR: get_return_url threw for #' . $order_id . ': ' . $e->getMessage() ); $redirect = wc_get_checkout_url(); }
		return array( 'result' => 'success', 'redirect' => $redirect );
		} catch ( Throwable $e ) {
			error_log( 'WC XMR: process_payment crashed for #' . $order_id . ': ' . $e->getMessage() );
			wc_add_notice( 'Payment processing failed unexpectedly. Please try again or contact support.', 'error' );
			return array( 'result' => 'failure' );
		}
	}

	/* --------------------------- Front-end display --------------------------- */

	public function thankyou_page( $order_id ) {
		$this->render_payment_details( $order_id );
	}

	public function view_order_page( $order_id ) {
		$order = wc_get_order( $order_id );
		if ( ! $order || $order->get_payment_method() !== $this->id ) return;
		if ( ! in_array( $order->get_status(), array( 'on-hold', 'pending' ), true ) ) return;
		$this->render_payment_details( $order_id );
	}
private function render_payment_details( $order_id ) {
		// Some themes/WC setups fire both woocommerce_thankyou and
		// woocommerce_view_order on the same page (e.g. the thank-you page
		// template also renders the "view order" partial). Without this
		// guard we'd print two payment boxes with duplicate element IDs,
		// and only the first would ever get its QR code populated.
		static $rendered = array();
		if ( isset( $rendered[ $order_id ] ) ) return;
		$rendered[ $order_id ] = true;

		$order = wc_get_order( $order_id );
		if ( ! $order ) return;

		$address = $order->get_meta( '_xmr_address' );
		$amount  = $order->get_meta( '_xmr_amount' );
		$expires = $order->get_meta( '_xmr_expires_at' );
		if ( ! $address || ! $amount ) return;

		// Unique per render call regardless - belt-and-braces in case this
		// is ever legitimately called more than once for the same order
		// (e.g. a theme injecting the template twice via a shortcode).
		static $instance = 0;
		$qr_id = 'wc-xmr-qr-' . ( ++$instance );

		$uri = 'monero:' . $address . '?tx_amount=' . rtrim( rtrim( number_format( (float) $amount, 12, '.', '' ), '0' ), '.' );

		wp_enqueue_script(
			'wc-xmr-qrcode',
			WC_XMR_PLUGIN_URL . 'qrcode.js',
			array(),
			'1.4.4',
			true
		);

		?>
		<style>
		.wc-xmr-box {
		    margin: 2em 0;
		    padding: 1.5em;
		    border: 1px solid rgba(255, 255, 255, 0.2);
		    border-radius: 8px;
		    background: rgba(0, 0, 0, 0.75);
		    color: #ffffff;
		}
		.wc-xmr-box h2, .wc-xmr-box p, .wc-xmr-box strong, .wc-xmr-box small { color: #ffffff !important; }
		.wc-xmr-box code {
		    color: #ffffff !important;
		    background: rgba(255, 255, 255, 0.15) !important;
		    padding: 0.4em 0.6em;
		    border-radius: 4px;
		    display: inline-block;
		    word-break: break-all;
		    font-family: monospace;
		}
		.wc-xmr-box .wc-xmr-addr { font-size: 0.95em; }
		.wc-xmr-box .wc-xmr-amount { font-size: 1.15em; font-weight: bold; }
		.wc-xmr-box .wc-xmr-muted { color: rgba(255, 255, 255, 0.8) !important; font-size: 0.9em; }
		.wc-xmr-box .wc-xmr-qr-wrap {
		    display: inline-block;
		    background: #ffffff;
		    padding: 12px;
		    border: 1px solid #eee;
		    border-radius: 4px;
		    margin: 1em 0;
		}
		.wc-xmr-box .wc-xmr-qr-wrap img { display: block; max-width: 280px; height: auto; }
		.wc-xmr-status-ok   { padding: 0.8em; background: rgba(46, 125, 46, 0.85); border-left: 4px solid #4caf50; color: #ffffff; }
		.wc-xmr-status-wait { padding: 0.8em; background: rgba(240, 160, 32, 0.85); border-left: 4px solid #ffb74d; color: #ffffff; }
		.wc-xmr-status-warn { padding: 0.8em; background: rgba(240, 160, 32, 0.85); border-left: 4px solid #ffb74d; color: #ffffff; }
		.wc-xmr-copy-btn {
		    background: rgba(255,255,255,0.15); color: #fff; border: 1px solid rgba(255,255,255,0.35);
		    border-radius: 4px; padding: 0.3em 0.7em; font-size: 0.85em; cursor: pointer; margin-left: 0.5em;
		    vertical-align: middle;
		}
		.wc-xmr-copy-btn:hover { background: rgba(255,255,255,0.28); }
		.wc-xmr-copy-btn.copied { background: rgba(76,175,80,0.85); border-color: #4caf50; }
		.wc-xmr-field-row { display: flex; align-items: center; flex-wrap: wrap; gap: 0.3em; }
		.wc-xmr-progress { margin: 1.2em 0; }
		.wc-xmr-progress-track {
		    height: 10px; border-radius: 5px; background: rgba(255,255,255,0.15);
		    overflow: hidden; position: relative;
		}
		.wc-xmr-progress-fill {
		    position: absolute; inset: 0; height: 100%; width: 100%;
		    background: linear-gradient(90deg,#ffb74d,#ff9d4d 45%,#4caf50);
		    /* clip-path (not width) so revealing progress never triggers layout
		       reflow -- this is the fix for the animation's outsized CPU/GPU
		       cost. Composited entirely on the GPU. */
		    clip-path: inset(0 100% 0 0);
		    transition: clip-path 4.2s cubic-bezier(.22,.85,.34,1);
		    overflow: hidden;
		}
		/* A soft light streak sweeping through the fill on a continuous loop --
		   pure CSS, runs on the compositor thread, completely independent of
		   the JS progress updates above, so it stays smooth regardless of
		   polling/tick rate. */
		.wc-xmr-progress-fill::after {
		    content: ""; position: absolute; top: 0; left: 0; height: 100%; width: 55%;
		    background: linear-gradient(100deg,
		        transparent 0%, transparent 30%,
		        rgba(255,255,255,.55) 45%, rgba(255,255,255,.9) 50%, rgba(255,255,255,.55) 55%,
		        transparent 70%, transparent 100%);
		    transform: translateX(-130%);
		    animation: wc-xmr-shine 2.6s linear infinite;
		    pointer-events: none;
		}
		@keyframes wc-xmr-shine { to { transform: translateX(320%); } }
		.wc-xmr-progress-labels {
		    display: flex; justify-content: space-between; margin-top: 0.5em;
		    font-size: 0.8em; color: rgba(255,255,255,0.6);
		}
		.wc-xmr-progress-labels span.active { color: #fff; font-weight: bold; }
		.wc-xmr-progress-labels span.closed-bad { color: #ff8a80; font-weight: bold; }
		</style>

		<section class="wc-xmr-box">
			<h2><?php esc_html_e( 'Monero Payment Details', 'wc-xmr' ); ?></h2>
			<?php if ( $this->instructions ) : ?>
				<p><?php echo wp_kses_post( wpautop( $this->instructions ) ); ?></p>
			<?php endif; ?>

			<?php $amount_str = rtrim( rtrim( number_format( (float) $amount, 12, '.', '' ), '0' ), '.' ); ?>
			<p><strong><?php esc_html_e( 'Amount:', 'wc-xmr' ); ?></strong>
				<span class="wc-xmr-field-row">
					<code class="wc-xmr-amount" id="wc-xmr-amount-<?php echo esc_attr( $qr_id ); ?>"><?php echo esc_html( $amount_str ); ?> XMR</code>
					<button type="button" class="wc-xmr-copy-btn" data-copy="<?php echo esc_attr( $amount_str ); ?>">Copy</button>
				</span>
			</p>

			<p><strong><?php esc_html_e( 'Address:', 'wc-xmr' ); ?></strong><br>
				<span class="wc-xmr-field-row">
					<code class="wc-xmr-addr"><?php echo esc_html( $address ); ?></code>
					<button type="button" class="wc-xmr-copy-btn" data-copy="<?php echo esc_attr( $address ); ?>">Copy</button>
				</span>
			</p>

			<div class="wc-xmr-qr-wrap">
				<img id="<?php echo esc_attr( $qr_id ); ?>" alt="Monero payment QR">
			</div>

			<?php
			$received = (float) $order->get_meta( '_xmr_received' );
			$confs    = (int) $order->get_meta( '_xmr_confirmations' );
			$min_amt  = (float) $order->get_meta( '_xmr_min_amount' );
			$conf_ok  = (int) $this->get_option( 'conf_processing', 1 );
			$conf_c   = (int) $this->get_option( 'conf_complete', 10 );
			$rate_at  = (int) $order->get_meta( '_xmr_rate_locked_at' );
			$stale_m  = (int) $this->get_option( 'rate_stale_warn', 30 );
			$init_tx_links = array_map( function( $tx ) {
				return array( 'hash' => $tx, 'links' => function_exists( 'wc_xmr_explorer_links' ) ? wc_xmr_explorer_links( $tx ) : array() );
			}, array_values( array_filter( explode( ',', (string) $order->get_meta( '_xmr_tx_hashes' ) ) ) ) );

			// Mirror wc_xmr_ajax_status()'s underpaid logic so a page load and
			// a poll tick always agree on the stage for the same order data.
			$init_terminal = in_array( $order->get_status(), array( 'processing', 'completed', 'cancelled', 'failed', 'refunded' ), true );
			$init_underpaid = ( $received > 0 && $min_amt > 0 && ( $received + 1e-12 ) < $min_amt && ! $init_terminal );

			$init_stage = 'awaiting';
			if ( $received > 0 && $confs < $conf_ok ) $init_stage = 'detected';
			if ( $received > 0 && $confs >= $conf_ok ) $init_stage = 'confirmed';
			if ( $init_underpaid ) $init_stage = 'underpaid';
			if ( in_array( $order->get_status(), array( 'processing', 'completed' ), true ) ) $init_stage = 'confirmed';
			if ( in_array( $order->get_status(), array( 'cancelled', 'failed', 'refunded' ), true ) ) $init_stage = 'closed';
			$min_str = rtrim( rtrim( number_format( $min_amt, 12, '.', '' ), '0' ), '.' );
			?>

			<div class="wc-xmr-progress" id="wc-xmr-progress-<?php echo esc_attr( $qr_id ); ?>" data-stage="<?php echo esc_attr( $init_stage ); ?>">
				<div class="wc-xmr-progress-track"><div class="wc-xmr-progress-fill"></div></div>
				<div class="wc-xmr-progress-labels">
					<span data-stage="awaiting"><?php esc_html_e( 'Awaiting payment', 'wc-xmr' ); ?></span>
					<span data-stage="detected"><?php esc_html_e( 'Payment detected', 'wc-xmr' ); ?></span>
					<span data-stage="confirmed"><?php esc_html_e( 'Confirmed', 'wc-xmr' ); ?></span>
				</div>
				<p class="wc-xmr-conf-text wc-xmr-muted" style="margin-top:0.6em;"></p>
				<p class="wc-xmr-tx-links wc-xmr-muted" style="margin-top:0.3em;font-size:0.85em;"></p>
			</div>

			<?php if ( $rate_at && $received <= 0 && ( time() - $rate_at ) > ( $stale_m * 60 ) ) : ?>
				<p class="wc-xmr-status-warn">This quote is more than <?php echo esc_html( $stale_m ); ?> minutes old. XMR price may have moved - if in doubt, contact us before paying.</p>
			<?php endif; ?>

			<?php if ( $expires ) : ?>
				<p class="wc-xmr-muted">
					<?php printf( esc_html__( 'Reserved until %s (UTC).', 'wc-xmr' ), esc_html( $expires ) ); ?>
				</p>
			<?php endif; ?>

			<p class="wc-xmr-muted"><?php esc_html_e( 'Order moves to Processing once payment is confirmed on-chain.', 'wc-xmr' ); ?></p>
		</section>

		<script>
		(function(){
			var uri = <?php echo wp_json_encode( $uri ); ?>;
			var qrId = <?php echo wp_json_encode( $qr_id ); ?>;
			var progressEl = document.getElementById('wc-xmr-progress-' + qrId);

			function renderQr(){
				if (typeof qrcode === 'undefined') { setTimeout(renderQr, 150); return; }
				var qr = qrcode(0, 'M');
				qr.addData(uri);
				qr.make();
				var img = document.getElementById(qrId);
				if (img) img.src = qr.createDataURL(6, 4);
			}
			if (document.readyState === 'loading') {
				document.addEventListener('DOMContentLoaded', renderQr);
			} else { renderQr(); }

			// Copy-to-clipboard buttons, with a fallback for browsers/contexts
			// (e.g. non-HTTPS) where the Clipboard API isn't available.
			document.querySelectorAll('.wc-xmr-copy-btn').forEach(function(btn){
				btn.addEventListener('click', function(){
					var text = btn.getAttribute('data-copy');
					var done = function(){
						var original = btn.textContent;
						btn.textContent = 'Copied!';
						btn.classList.add('copied');
						setTimeout(function(){ btn.textContent = original; btn.classList.remove('copied'); }, 1500);
					};
					if (navigator.clipboard && window.isSecureContext) {
						navigator.clipboard.writeText(text).then(done).catch(function(){ fallbackCopy(text, done); });
					} else {
						fallbackCopy(text, done);
					}
				});
			});
			function fallbackCopy(text, done){
				var ta = document.createElement('textarea');
				ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
				document.body.appendChild(ta); ta.focus(); ta.select();
				try { document.execCommand('copy'); done(); } catch (e) {}
				document.body.removeChild(ta);
			}

			// Live progress bar. Polls a lightweight endpoint (gated by this
			// order's own order_key, same as WooCommerce's own guest order
			// access) so the customer sees confirmations tick up without
			// having to reload the page.
			var statusUrl = <?php echo wp_json_encode( add_query_arg( array(
				'action'   => 'wc_xmr_status',
				'order_id' => $order_id,
				'key'      => $order->get_order_key(),
			), admin_url( 'admin-ajax.php' ) ) ); ?>;

			// Cosmetic-only "creep": paces the bar between real confirmation
			// checks. It never claims completion itself -- 100% is set
			// exclusively by the server actually reporting "confirmed".
			//
			// Starts at 50% the instant payment is first seen, lining up
			// with the "Payment detected" label (the visual midpoint of the
			// three-stage track) rather than an arbitrary low value that
			// didn't correspond to anything on screen.
			//
			// Moves on an exponential decay curve -- fast at first, then
			// continuously slowing -- with a ~5 minute time constant, so it
			// never looks "stuck" early on but also never races to the cap
			// and sits there. Anchored to a real timestamp persisted in
			// localStorage (keyed to this order) so refreshing the page
			// resumes from the true elapsed time instead of restarting from
			// scratch, which is what looked suspicious before.
			var orderId = <?php echo wp_json_encode( (string) $order_id ); ?>;
			var ANIM_KEY = 'wc_xmr_progress_anchor_' + orderId;
			var CREEP_START_PCT = 50;
			var CREEP_CAP_PCT   = 96;
			var CREEP_TAU_MS    = 90000;  // ~1.5 min time constant
			var CREEP_UPDATE_MS = 4000;   // push a new target every 4s; CSS transition smooths between updates -- no per-second layout writes

			var creepAnchorTime = null;
			var creepTimer = null;

			function loadAnchor() {
				try {
					var raw = localStorage.getItem(ANIM_KEY);
					if (raw) {
						var obj = JSON.parse(raw);
						if (obj && obj.anchorTime) return obj.anchorTime;
					}
				} catch (e) {}
				return null;
			}
			function saveAnchor(t) {
				try { localStorage.setItem(ANIM_KEY, JSON.stringify({ anchorTime: t })); } catch (e) {}
			}
			function clearAnchor() {
				try { localStorage.removeItem(ANIM_KEY); } catch (e) {}
			}

			function creepPctNow() {
				var elapsed = Math.max(0, Date.now() - creepAnchorTime);
				// 1 - e^(-t/tau): starts fast, decays continuously -- true
				// exponential slowdown rather than a linear crawl that
				// suddenly stops.
				var frac = 1 - Math.exp(-elapsed / CREEP_TAU_MS);
				return CREEP_START_PCT + (CREEP_CAP_PCT - CREEP_START_PCT) * frac;
			}

			function applyClip(pct) {
				var fill = progressEl && progressEl.querySelector('.wc-xmr-progress-fill');
				if (fill) fill.style.clipPath = 'inset(0 ' + (100 - pct) + '% 0 0)';
			}

			function startCreep() {
				if (!creepAnchorTime) {
					creepAnchorTime = loadAnchor() || Date.now();
					saveAnchor(creepAnchorTime);
				}
				applyClip(creepPctNow());
				if (creepTimer) return; // already ticking, don't restart/reset
				creepTimer = setInterval(function () { applyClip(creepPctNow()); }, CREEP_UPDATE_MS);
			}

			function stopCreep() {
				if (creepTimer) { clearInterval(creepTimer); creepTimer = null; }
			}

			function renderTxLinks(txLinks){
				var el = progressEl && progressEl.parentNode && progressEl.parentNode.querySelector('.wc-xmr-tx-links');
				if (!el) return;
				if (!txLinks || !txLinks.length) { el.innerHTML = ''; return; }
				el.innerHTML = 'Transaction' + (txLinks.length > 1 ? 's' : '') + ': ' + txLinks.map(function(t){
					var short = t.hash.slice(0, 10) + '...';
					var linkParts = (t.links || []).map(function(l){
						return '<a href="' + l.url.replace(/"/g, '&quot;') + '" target="_blank" rel="noopener noreferrer">' + l.label.replace(/</g,'&lt;') + ' </a>';
					}).join(' · ');
					return '<code title="' + t.hash + '">' + short + '</code>' + (linkParts ? ' ' + linkParts : '');
				}).join(' &nbsp; ');
			}

			function applyStage(stage, confs, confP, received, txLinks, minAmt){
				if (!progressEl) return;
				progressEl.setAttribute('data-stage', stage);

				if (typeof txLinks !== 'undefined') renderTxLinks(txLinks);

				if (stage === 'detected') {
					// startCreep() itself no-ops on the timer if one's already
					// running, so repeated polls with the same stage don't
					// reset or jump the animation -- it just keeps creeping.
					startCreep();
				} else if (stage === 'underpaid') {
					// Payment seen but short of the requested minimum: park
					// the bar at the "detected" midpoint instead of letting
					// the creep animation imply completion that isn't real.
					// Keep polling (the poll loop only stops on
					// confirmed/closed) so a top-up flips this to confirmed.
					stopCreep();
					applyClip(50);
				} else {
					stopCreep();
					applyClip(stage === 'confirmed' ? 100 : 0);
					if (stage === 'confirmed' || stage === 'closed') clearAnchor();
				}

				var labelStage = (stage === 'underpaid') ? 'detected' : stage;
				progressEl.querySelectorAll('.wc-xmr-progress-labels span').forEach(function(el){
					el.classList.toggle('active', el.getAttribute('data-stage') === labelStage);
				});

				var text = progressEl.querySelector('.wc-xmr-conf-text');
				if (text) {
					if (stage === 'awaiting') {
						text.textContent = '';
					} else if (stage === 'detected') {
						text.textContent = 'Confirmations: ' + confs + ' / ' + confP + '   ·   Received: ' + received + ' XMR';
					} else if (stage === 'underpaid') {
						text.textContent = 'Received ' + received + ' of ' + minAmt + ' XMR - payment is short of the requested amount. Send the remainder to the same address; this page updates automatically.';
					} else if (stage === 'confirmed') {
						text.textContent = 'Payment confirmed (' + confs + ' confirmations). Order is being processed.';
					} else if (stage === 'closed') {
						text.textContent = 'This order is no longer awaiting payment.';
					}
				}
			}

			var initialStage = progressEl ? progressEl.getAttribute('data-stage') : 'awaiting';
			applyStage(initialStage, <?php echo (int) $confs; ?>, <?php echo (int) $conf_ok; ?>, <?php echo wp_json_encode( $amount_str ); ?>, <?php echo wp_json_encode( $init_tx_links ); ?>, <?php echo wp_json_encode( $min_str ); ?>);

			var polling = ( initialStage !== 'confirmed' && initialStage !== 'closed' );
			function poll(){
				if (!polling) return;
				fetch(statusUrl, { credentials: 'same-origin' })
					.then(function(r){ return r.json(); })
					.then(function(res){
						if (!res || !res.success || !res.data) return;
						var d = res.data;
						var receivedStr = (Math.round(d.received * 1e12) / 1e12).toString();
						applyStage(d.stage, d.confirmations, d.conf_processing, receivedStr, d.tx_links, d.min);
						if (d.stage === 'confirmed' || d.stage === 'closed') {
							polling = false;
						}
					})
					.catch(function(){ /* transient network hiccup - try again next tick */ });
			}
			// The server only actually re-checks the blockchain every
			// "Poll interval" setting (default 5 min) - polling this endpoint
			// much faster than that just hammers the server for data that
			// cannot have changed yet. We poll at roughly 1/6th of the real
			// server interval (clamped to a sane 20s-90s range); the visual
			// creep above is what keeps the bar feeling live in between.
			var serverPollSeconds = <?php echo (int) max( 2, min( 60, (int) $this->get_option( 'poll_interval', 5 ) ) ) * 60; ?>;
			var clientPollMs = Math.max( 20000, Math.min( 90000, Math.round( serverPollSeconds * 1000 / 6 ) ) );
			if (polling) setInterval(poll, clientPollMs);
			})();
		</script>
		<?php
	}

	public function email_instructions( $order, $sent_to_admin, $plain_text = false ) {
		if ( $order->get_payment_method() !== $this->id ) return;
		if ( ! in_array( $order->get_status(), array( 'on-hold', 'pending' ), true ) ) return;

		$address = $order->get_meta( '_xmr_address' );
		$amount  = $order->get_meta( '_xmr_amount' );
		if ( ! $address || ! $amount ) return;

		$amount_str = rtrim( rtrim( number_format( (float) $amount, 12, '.', '' ), '0' ), '.' );

		if ( $plain_text ) {
			echo "\n\n" . __( 'MONERO PAYMENT', 'wc-xmr' ) . "\n";
			echo __( 'Amount: ', 'wc-xmr' ) . $amount_str . " XMR\n";
			echo __( 'Address: ', 'wc-xmr' ) . $address . "\n\n";
		} else {
			echo '<h2>' . esc_html__( 'Monero Payment', 'wc-xmr' ) . '</h2>';
			echo '<p><strong>' . esc_html__( 'Amount:', 'wc-xmr' ) . '</strong> <code>' . esc_html( $amount_str ) . ' XMR</code></p>';
			echo '<p><strong>' . esc_html__( 'Address:', 'wc-xmr' ) . '</strong><br><code style="word-break:break-all;">' . esc_html( $address ) . '</code></p>';
		}
	}
}