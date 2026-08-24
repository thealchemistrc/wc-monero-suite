<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WC_XMR_RPC {

    private $url; private $user; private $pass; private $timeout;

    // Kept deliberately small: this can run synchronously during checkout
    // (address generation), so a long retry/backoff loop would just make a
    // customer stare at a hung page while wallet-rpc is having a bad day.
    // One quick retry catches most of the "occasionally flaky" cases
    // (exactly the kind of thing that shows up more often on Windows)
    // without meaningfully hurting checkout latency.
    const MAX_ATTEMPTS = 2;
    const RETRY_DELAY_US = 400000; // 0.4s

    // Default timeout suits the light, checkout-time calls (address
    // creation, get_version). get_transfers -- what the background poller
    // uses to check for new confirmations -- can legitimately take much
    // longer, especially right after new blocks land and wallet-rpc has to
    // rescan/catch up, so callers running in a non-interactive context
    // (cron) should pass a higher $timeout explicitly rather than everyone
    // sharing one value tuned for "customer is staring at the checkout page".
    public function __construct( $url, $user = '', $pass = '', $timeout = 15 ) {
        $this->url = $url; $this->user = $user; $this->pass = $pass; $this->timeout = $timeout;
    }

    public function call( $method, $params = array() ) {
        $body = wp_json_encode( array(
            'jsonrpc' => '2.0', 'id' => '0', 'method' => $method, 'params' => (object) $params,
        ) );
        if ( $body === false ) {
            error_log( 'WC XMR: RPC wp_json_encode failed for method ' . $method . ': ' . json_last_error_msg() );
            return new WP_Error( 'xmr_rpc_encode', 'Failed to encode RPC request body.' );
        }

        if ( empty( $this->url ) ) {
            error_log( 'WC XMR: RPC call ' . $method . ' attempted with empty URL.' );
            return new WP_Error( 'xmr_rpc_no_url', 'Wallet-rpc URL is not configured.' );
        }

        $last_error = null;

        for ( $attempt = 1; $attempt <= self::MAX_ATTEMPTS; $attempt++ ) {
            $result = $this->curl_call( $body );

            if ( $result instanceof WP_Error ) {
                $last_error = $result;
                if ( $attempt < self::MAX_ATTEMPTS ) {
                    error_log( sprintf( 'WC XMR: RPC %s attempt %d/%d failed (%s) - retrying in %dms.', $method, $attempt, self::MAX_ATTEMPTS, $result->get_error_code(), self::RETRY_DELAY_US / 1000 ) );
                    usleep( self::RETRY_DELAY_US ); continue;
                }
                error_log( sprintf( 'WC XMR: RPC %s failed after %d attempt(s): [%s] %s', $method, $attempt, $result->get_error_code(), $result->get_error_message() ) );
                return $last_error;
            }

            list( $code, $raw ) = $result;

            if ( $code === 401 ) {
                // Wrong credentials isn't a transient problem - retrying won't help.
                error_log( 'WC XMR: RPC ' . $method . ' got HTTP 401 - check wallet-rpc --rpc-login credentials.' );
                return new WP_Error( 'xmr_rpc_auth', 'Wallet-rpc rejected the configured username/password (HTTP 401). Check that the credentials saved here match wallet-rpc\'s --rpc-login.' );
            }

            if ( $code === 403 ) {
                error_log( 'WC XMR: RPC ' . $method . ' got HTTP 403.' );
                return new WP_Error( 'xmr_rpc_403', "Wallet-rpc returned HTTP 403 Forbidden for {$method} - check firewall/proxy rules or wallet-rpc --rpc-access-control-origins." );
            }

            if ( $code === 407 ) {
                error_log( 'WC XMR: RPC ' . $method . ' got HTTP 407 Proxy Auth Required.' );
                return new WP_Error( 'xmr_rpc_407', 'Proxy authentication required (HTTP 407). Check the proxy username/password in gateway settings.' );
            }

            if ( $code === 429 ) {
                $last_error = new WP_Error( 'xmr_rpc_429', "Wallet-rpc rate-limited this request (HTTP 429) for {$method}." );
                if ( $attempt < self::MAX_ATTEMPTS ) {
                    error_log( sprintf( 'WC XMR: RPC %s got HTTP 429 - retrying in %dms.', $method, self::RETRY_DELAY_US / 1000 ) );
                    usleep( self::RETRY_DELAY_US ); continue;
                }
                error_log( 'WC XMR: RPC ' . $method . ' rate-limited (HTTP 429) after ' . $attempt . ' attempt(s).' );
                return $last_error;
            }

            if ( $code >= 500 ) {
                $last_error = new WP_Error( 'xmr_rpc_5xx', "Wallet-rpc responded but with HTTP {$code} - it's reachable but erroring internally. Common causes: the wallet file is locked/busy (another process has it open), it's still syncing, or it just crashed and needs a restart." );
                if ( $attempt < self::MAX_ATTEMPTS ) {
                    error_log( sprintf( 'WC XMR: RPC %s got HTTP %d - retrying in %dms.', $method, $code, self::RETRY_DELAY_US / 1000 ) );
                    usleep( self::RETRY_DELAY_US ); continue;
                }
                error_log( sprintf( 'WC XMR: RPC %s got HTTP %d after %d attempt(s).', $method, $code, $attempt ) );
                return $last_error;
            }

            if ( $code < 200 || $code >= 300 ) {
                error_log( sprintf( 'WC XMR: RPC %s got unexpected HTTP %d.', $method, $code ) );
                return new WP_Error( 'xmr_rpc_http_' . $code, "Wallet-rpc returned unexpected HTTP {$code} for {$method}." );
            }

            $data = json_decode( $raw, true );
            if ( json_last_error() !== JSON_ERROR_NONE ) {
                $snippet = substr( preg_replace( '/\s+/', ' ', (string) $raw ), 0, 200 );
                $last_error = new WP_Error( 'xmr_rpc_bad_json', "Wallet-rpc returned invalid JSON for {$method} (" . json_last_error_msg() . '). First 200 chars: ' . ( $snippet !== '' ? $snippet : '(empty body)' ) );
                if ( $attempt < self::MAX_ATTEMPTS ) {
                    error_log( sprintf( 'WC XMR: RPC %s got invalid JSON - retrying. Snippet: %s', $method, $snippet ) );
                    usleep( self::RETRY_DELAY_US ); continue;
                }
                error_log( sprintf( 'WC XMR: RPC %s got invalid JSON after %d attempt(s): %s', $method, $attempt, json_last_error_msg() ) );
                return $last_error;
            }

            // A response that isn't shaped like JSON-RPC (no 'result' AND no
            // 'error' key) must NOT be silently treated as "empty success" -
            // that would make a broken/garbled response from a flaky
            // wallet-rpc process look identical to "genuinely no transfers
            // yet", which is exactly the kind of quiet miss you don't want
            // in a payment-detection path.
            if ( ! is_array( $data ) || ( ! array_key_exists( 'result', $data ) && ! array_key_exists( 'error', $data ) ) ) {
                $snippet = substr( preg_replace( '/\s+/', ' ', (string) $raw ), 0, 200 );
                $last_error = new WP_Error( 'xmr_rpc_bad_response', "Wallet-rpc returned something that isn't valid JSON-RPC - possibly a proxy error page, a crashed/restarting process, or the wrong URL/port. First 200 chars of the response: " . ( $snippet !== '' ? $snippet : '(empty body)' ) );
                if ( $attempt < self::MAX_ATTEMPTS ) {
                    error_log( sprintf( 'WC XMR: RPC %s got non-JSON-RPC response - retrying. Snippet: %s', $method, $snippet ) );
                    usleep( self::RETRY_DELAY_US ); continue;
                }
                error_log( sprintf( 'WC XMR: RPC %s got non-JSON-RPC response after %d attempt(s).', $method, $attempt ) );
                return $last_error;
            }

            if ( isset( $data['error'] ) ) {
                $msg = $data['error']['message'] ?? 'RPC error';
                $code_val = $data['error']['code'] ?? '?';
                error_log( sprintf( 'WC XMR: RPC %s returned JSON-RPC error %s: %s', $method, $code_val, $msg ) );
                return new WP_Error( 'xmr_rpc', $msg );
            }
            return $data['result'] ?? array();
        }

        error_log( 'WC XMR: RPC ' . $method . ' exhausted all attempts without a result.' );
        return $last_error ?: new WP_Error( 'xmr_rpc_unknown', 'Wallet-rpc call failed for an unknown reason.' );
    }

    /**
     * Performs the actual HTTP exchange via raw cURL rather than
     * wp_remote_post(). This is deliberate: monero-wallet-rpc (epee) ties
     * its digest-auth nonce to the underlying TCP connection. Two separate
     * wp_remote_post() calls - one to harvest the WWW-Authenticate
     * challenge, one to send the computed Authorization header - each open
     * a fresh connection via WP's HTTP API, so by the time the second
     * request arrives the nonce is already stale from the server's
     * perspective (HTTP 401 with stale=true), independent of whether the
     * digest math and credentials are correct. CURLOPT_HTTPAUTH =
     * CURLAUTH_DIGEST lets libcurl perform the challenge/response on one
     * real persistent connection, the same way curl.exe's --digest flag
     * does, which is what confirmed this works at all.
     *
     * Returns array( $http_code, $raw_body ) on success, WP_Error on a
     * transport-level failure (couldn't connect, DNS, TLS, timeout, etc).
     */
    private function curl_call( $body ) {
        if ( ! function_exists( 'curl_init' ) ) {
            error_log( 'WC XMR: curl_init not available - cURL extension missing.' );
            return new WP_Error( 'xmr_rpc_no_curl', 'PHP\'s cURL extension is required to talk to wallet-rpc (for digest auth support) and is not available on this server.' );
        }

        if ( empty( $this->url ) || ! filter_var( $this->url, FILTER_VALIDATE_URL ) ) {
            error_log( 'WC XMR: curl_call called with invalid URL: ' . var_export( $this->url, true ) );
            return new WP_Error( 'xmr_rpc_bad_url', 'Wallet-rpc URL is empty or not a valid URL: ' . $this->url );
        }

        $ch = curl_init( $this->url );
        if ( $ch === false ) {
            error_log( 'WC XMR: curl_init failed for URL: ' . $this->url );
            return new WP_Error( 'xmr_rpc_curl_init', 'Failed to initialise cURL for wallet-rpc URL: ' . $this->url );
        }
        $timeout = max( 5, min( 120, (int) $this->timeout ) );
        $opts = array(
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_HTTPHEADER     => array( 'Content-Type: application/json' ),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => false,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS      => 0,
            CURLOPT_PROTOCOLS      => defined( 'CURLPROTO_HTTP' ) && defined( 'CURLPROTO_HTTPS' ) ? ( CURLPROTO_HTTP | CURLPROTO_HTTPS ) : 0,
        );
        if ( $opts[ CURLOPT_PROTOCOLS ] === 0 ) {
            unset( $opts[ CURLOPT_PROTOCOLS ] );
        }

        if ( $this->user !== '' ) {
            $opts[ CURLOPT_HTTPAUTH ] = CURLAUTH_DIGEST;
            $opts[ CURLOPT_USERPWD ]  = $this->user . ':' . $this->pass;
        }

        // Re-apply this plugin's proxy setting here since we're bypassing
        // WC_XMR_HTTP/wp_remote_post for this call - keeps Mullvad/SOCKS5
        // proxy support working the same as price-lookup calls.
        if ( class_exists( 'WC_XMR_HTTP' ) ) {
            $p = WC_XMR_HTTP::proxy_settings();
            if ( $p['enabled'] && $p['host'] && $p['port'] ) {
                $types = array(
                    'http'    => defined( 'CURLPROXY_HTTP' ) ? CURLPROXY_HTTP : 0,
                    'socks5'  => defined( 'CURLPROXY_SOCKS5' ) ? CURLPROXY_SOCKS5 : 5,
                    'socks5h' => defined( 'CURLPROXY_SOCKS5_HOSTNAME' ) ? CURLPROXY_SOCKS5_HOSTNAME : 7,
                );
                $opts[ CURLOPT_PROXY ]     = $p['host'];
                $opts[ CURLOPT_PROXYPORT ] = (int) $p['port'];
                $opts[ CURLOPT_PROXYTYPE ] = $types[ $p['type'] ] ?? $types['socks5h'];
                if ( $p['user'] !== '' ) {
                    $opts[ CURLOPT_PROXYUSERPWD ] = $p['user'] . ':' . $p['pass'];
                }
                $opts[ CURLOPT_SSL_VERIFYPEER ] = true;
                $opts[ CURLOPT_SSL_VERIFYHOST ] = 2;
            }
        }

        if ( ! curl_setopt_array( $ch, $opts ) ) {
            $err = curl_error( $ch );
            curl_close( $ch );
            error_log( 'WC XMR: curl_setopt_array failed: ' . $err );
            return new WP_Error( 'xmr_rpc_curl_opts', 'Failed to configure cURL options for wallet-rpc: ' . $err );
        }
        $raw_body = curl_exec( $ch );

        if ( $raw_body === false ) {
            $errno = curl_errno( $ch );
            $err   = curl_error( $ch );
            curl_close( $ch );
            return $this->classify_curl_error( $errno, $err );
        }

        $code = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
        if ( $code === 0 ) {
            $err = curl_error( $ch );
            curl_close( $ch );
            error_log( 'WC XMR: curl_exec returned HTTP 0 for ' . $this->url . ': ' . $err );
            return new WP_Error( 'xmr_rpc_no_http_code', "Wallet-rpc at {$this->url} returned no HTTP status code. cURL error: {$err}" );
        }
        curl_close( $ch );

        return array( $code, $raw_body );
    }

    private function classify_curl_error( $errno, $err ) {
        $url = $this->url;
        $err_lc = strtolower( (string) $err );

        if ( ( defined( 'CURLE_OPERATION_TIMEOUTED' ) && $errno === CURLE_OPERATION_TIMEOUTED ) || strpos( $err_lc, 'timed out' ) !== false || strpos( $err_lc, 'timeout' ) !== false ) {
            return new WP_Error( 'xmr_rpc_timeout', "Wallet-rpc at {$url} didn't respond in time. If this is occasional, it may just be busy (rescanning, under load); if it's constant, confirm the process is actually running and responsive." );
        }
        if ( ( defined( 'CURLE_COULDNT_CONNECT' ) && $errno === CURLE_COULDNT_CONNECT ) || strpos( $err_lc, 'refused' ) !== false ) {
            return new WP_Error( 'xmr_rpc_refused', "Connection refused at {$url} - nothing is listening there. Check wallet-rpc is actually running, the port matches what's configured here, and (on Windows especially) that a firewall or antivirus isn't blocking the port." );
        }
        if ( ( defined( 'CURLE_COULDNT_RESOLVE_HOST' ) && $errno === CURLE_COULDNT_RESOLVE_HOST ) || strpos( $err_lc, 'resolve' ) !== false || strpos( $err_lc, 'could not resolve' ) !== false ) {
            return new WP_Error( 'xmr_rpc_dns', "Could not resolve the hostname in {$url} - double-check it's correct and, if it's a local hostname, that it actually resolves from this server." );
        }
        if ( ( defined( 'CURLE_SSL_CONNECT_ERROR' ) && $errno === CURLE_SSL_CONNECT_ERROR ) || ( defined( 'CURLE_SSL_CACERT' ) && $errno === CURLE_SSL_CACERT ) || strpos( $err_lc, 'ssl' ) !== false || strpos( $err_lc, 'certificate' ) !== false ) {
            return new WP_Error( 'xmr_rpc_tls', "TLS/certificate error connecting to {$url}: {$err}" );
        }
        if ( defined( 'CURLE_COULDNT_RESOLVE_PROXY' ) && $errno === CURLE_COULDNT_RESOLVE_PROXY ) {
            return new WP_Error( 'xmr_rpc_proxy_dns', "Could not resolve proxy host for wallet-rpc at {$url}: {$err}" );
        }
        if ( defined( 'CURLE_RECV_ERROR' ) && $errno === CURLE_RECV_ERROR ) {
            return new WP_Error( 'xmr_rpc_recv', "Connection dropped while reading wallet-rpc response at {$url}: {$err}" );
        }
        $label = $errno ? "cURL {$errno}" : 'transport';
        return new WP_Error( 'xmr_rpc_transport', "Couldn't reach wallet-rpc at {$url} [{$label}]: {$err}" );
    }
}
