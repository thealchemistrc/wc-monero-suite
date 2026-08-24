<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Historical address audit - detects when pushed addresses diverge from
 * previously-seen values, indicating a possible wallet swap, compromised
 * device, or attacker injecting addresses from a different wallet.
 *
 * Checks performed on every address push:
 *   1. Address reuse - pushed address already exists in reservations table
 *   2. Index reassignment - same index, different address than last push
 *   3. Index range anomaly - sudden jump far outside historical index range
 *
 * Works with 1 device (temporal consistency) or N devices (cross-phone comparison).
 */
class WC_XMR_Push_Audit {

	const OPTION          = 'wc_xmr_push_address_history';
	const MAX_INDEX_JUMP  = 50;   // max new indices allowed in a single push
	const MAX_HISTORY_AGE = 86400 * 30; // prune entries older than 30 days
	const MAX_INDICES_PER_PHONE = 2000; // cap per-device index history - active devices would otherwise grow it unbounded

	/**
	 * Run all audit checks on an incoming address push.
	 *
	 * @param string $phone_pk  Ed25519 public key hex of the pushing device (empty if unsigned).
	 * @param array  $addresses Array of address entries, each with 'address' and 'index' keys.
	 * @return array Array of warnings/errors: array( array( 'level' => 'warn'|'error', 'msg' => '...' ) )
	 */
	public static function audit( $phone_pk, $addresses ) {
		$alerts = array();

		if ( empty( $addresses ) || ! is_array( $addresses ) ) {
			return $alerts;
		}

		// Check 1: Address reuse in reservations table.
		$reuse_alerts = self::check_address_reuse( $addresses );
		$alerts = array_merge( $alerts, $reuse_alerts );

		// Checks 2 & 3 require per-device history.
		if ( $phone_pk === '' ) {
			// Unsigned push - skip per-device checks, still record for future.
			self::record_push( $phone_pk, $addresses );
			return $alerts;
		}

		// Check 2: Index reassignment (same index, different address).
		$reassign_alerts = self::check_index_reassignment( $phone_pk, $addresses );
		$alerts = array_merge( $alerts, $reassign_alerts );

		// Check 3: Index range anomaly.
		$range_alerts = self::check_index_range( $phone_pk, $addresses );
		$alerts = array_merge( $alerts, $range_alerts );

		// Record this push for future audits.
		self::record_push( $phone_pk, $addresses );

		return $alerts;
	}

	/**
	 * Check if any pushed address already exists in the reservations table.
	 *
	 * Severity is calibrated: matching an ACTIVE (reserved/detected)
	 * reservation usually means the device re-announced an address that is
	 * currently assigned to an order (e.g. wallet restored/re-created) -
	 * that is recoverable, because process_confirmation()'s address-based
	 * fallback can then patch the stale reservation. Matching only
	 * historical rows is informational. Neither alone proves compromise;
	 * genuine wallet-swap detection lives in check_index_reassignment().
	 */
	private static function check_address_reuse( $addresses ) {
		global $wpdb;
		$t = $wpdb->prefix . 'wc_xmr_reservations';
		$alerts = array();

		// Build a list of address strings to check.
		$addr_list = array();
		foreach ( $addresses as $entry ) {
			$addr = is_array( $entry ) ? ( $entry['address'] ?? '' ) : (string) $entry;
			if ( $addr !== '' ) {
				$addr_list[] = $addr;
			}
		}

		if ( empty( $addr_list ) ) return $alerts;

		// Query reservations table for any of these addresses.
		$placeholders = implode( ',', array_fill( 0, count( $addr_list ), '%s' ) );
		try {
			$found = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT DISTINCT address, status FROM {$t} WHERE address IN ({$placeholders}) LIMIT 20",
					$addr_list
				)
			);
		} catch ( Throwable $e ) {
			error_log( 'WC XMR Push Audit: address reuse query failed: ' . $e->getMessage() );
			return $alerts;
		}

		if ( empty( $found ) || ! is_array( $found ) ) return $alerts;

		$active = array();
		$historical = array();
		foreach ( $found as $row ) {
			if ( in_array( $row->status ?? '', array( 'reserved', 'detected' ), true ) ) {
				$active[ $row->address ] = true;
			} else {
				$historical[ $row->address ] = true;
			}
		}

		if ( ! empty( $active ) ) {
			$alerts[] = array(
				'level' => 'warn',
				'msg'   => sprintf(
					'%d pushed address(es) match ACTIVE order reservations - the device re-announced in-use addresses (wallet restored?). Confirmation fallback can recover these orders; verify on the next payment. Addresses: %s',
					count( $active ),
					implode( ', ', array_map( function( $a ) { return substr( $a, 0, 12 ) . '...'; }, array_keys( $active ) ) )
				),
			);
		}
		if ( ! empty( $historical ) ) {
			$alerts[] = array(
				'level' => 'warn',
				'msg'   => sprintf(
					'%d pushed address(es) were used by past orders (no active reservations) - benign re-push, e.g. after a wallet restore. Addresses: %s',
					count( $historical ),
					implode( ', ', array_map( function( $a ) { return substr( $a, 0, 12 ) . '...'; }, array_keys( $historical ) ) )
				),
			);
		}

		return $alerts;
	}

	/**
	 * Check if any index now maps to a different address than before.
	 * This is the strongest signal of a wallet change.
	 */
	private static function check_index_reassignment( $phone_pk, $addresses ) {
		$history = self::get_history();
		$phone_history = $history[ $phone_pk ] ?? null;
		$alerts = array();

		if ( $phone_history === null || empty( $phone_history['indices'] ) ) {
			return $alerts; // First push from this device - nothing to compare.
		}

		$reassignments = array();
		foreach ( $addresses as $entry ) {
			$idx  = (int) ( is_array( $entry ) ? ( $entry['index'] ?? -1 ) : -1 );
			$addr = is_array( $entry ) ? ( $entry['address'] ?? '' ) : (string) $entry;
			if ( $idx < 0 || $addr === '' ) continue;

			$prev = $phone_history['indices'][ $idx ] ?? null;
			if ( $prev !== null && $prev['address'] !== $addr ) {
				$reassignments[] = array(
					'index'    => $idx,
					'previous' => $prev['address'],
					'current'  => $addr,
				);
			}
		}

		if ( ! empty( $reassignments ) ) {
			$details = array();
			foreach ( $reassignments as $r ) {
				$details[] = sprintf(
					'index %d: %s → %s',
					$r['index'],
					substr( $r['previous'], 0, 12 ) . '...',
					substr( $r['current'], 0, 12 ) . '...'
				);
			}
			$alerts[] = array(
				'level' => 'error',
				'msg'   => sprintf(
					'CRITICAL: %d subaddress index(es) changed address - possible wallet swap or compromise. %s',
					count( $reassignments ),
					implode( '; ', array_slice( $details, 0, 5 ) )
				),
			);
		}

		return $alerts;
	}

	/**
	 * Check if the index range has suddenly jumped far outside historical bounds.
	 * A device that was pushing indices 0-499 suddenly pushing 5000-5499 is suspicious.
	 */
	private static function check_index_range( $phone_pk, $addresses ) {
		$history = self::get_history();
		$phone_history = $history[ $phone_pk ] ?? null;
		$alerts = array();

		if ( $phone_history === null || empty( $phone_history['indices'] ) ) {
			return $alerts; // First push - nothing to compare.
		}

		// Find the max index in this push.
		$push_max = 0;
		$push_indices = array();
		foreach ( $addresses as $entry ) {
			$idx = (int) ( is_array( $entry ) ? ( $entry['index'] ?? -1 ) : -1 );
			if ( $idx >= 0 ) {
				$push_indices[] = $idx;
				if ( $idx > $push_max ) $push_max = $idx;
			}
		}

		if ( empty( $push_indices ) ) return $alerts;

		// Find the historical max index.
		$hist_max = 0;
		$hist_indices = array_keys( $phone_history['indices'] );
		foreach ( $hist_indices as $idx ) {
			if ( (int) $idx > $hist_max ) $hist_max = (int) $idx;
		}

		// Count how many indices in this push are brand new (not in history).
		$new_count = 0;
		foreach ( $push_indices as $idx ) {
			if ( ! isset( $phone_history['indices'][ $idx ] ) ) {
				$new_count++;
			}
		}

		// Alert if too many new indices at once.
		if ( $new_count > self::MAX_INDEX_JUMP ) {
			$alerts[] = array(
				'level' => 'warn',
				'msg'   => sprintf(
					'Unusual: %d new subaddress indices in a single push (threshold: %d). Historical max index: %d, push max: %d.',
					$new_count, self::MAX_INDEX_JUMP, $hist_max, $push_max
				),
			);
		}

		// Alert if the push max is far beyond historical max (gap > 200).
		if ( $hist_max > 0 && ( $push_max - $hist_max ) > 200 ) {
			$alerts[] = array(
				'level' => 'warn',
				'msg'   => sprintf(
					'Index range jump: historical max index was %d, now pushing up to %d (gap: %d). Possible different wallet.',
					$hist_max, $push_max, $push_max - $hist_max
				),
			);
		}

		return $alerts;
	}

	/**
	 * Record a push for future audit comparisons.
	 */
	private static function record_push( $phone_pk, $addresses ) {
		$history = self::get_history();
		$now = time();

		// Use empty string key for unsigned pushes.
		$key = ( $phone_pk === '' ) ? '_unsigned' : $phone_pk;

		if ( ! isset( $history[ $key ] ) ) {
			$history[ $key ] = array(
				'first_seen' => $now,
				'last_seen'  => $now,
				'indices'    => array(),
			);
		}

		$history[ $key ]['last_seen'] = $now;

		foreach ( $addresses as $entry ) {
			$idx  = (int) ( is_array( $entry ) ? ( $entry['index'] ?? -1 ) : -1 );
			$addr = is_array( $entry ) ? ( $entry['address'] ?? '' ) : (string) $entry;
			if ( $idx < 0 || $addr === '' ) continue;

			if ( isset( $history[ $key ]['indices'][ $idx ] ) ) {
				$history[ $key ]['indices'][ $idx ]['last_seen'] = $now;
				// Don't overwrite address - we want to detect changes, not silently update.
			} else {
				$history[ $key ]['indices'][ $idx ] = array(
					'address'    => $addr,
					'first_seen' => $now,
					'last_seen'  => $now,
				);
			}
		}

		// Prune old entries.
		$cutoff = $now - self::MAX_HISTORY_AGE;
		foreach ( $history as $pk => $phone_data ) {
			if ( $phone_data['last_seen'] < $cutoff ) {
				unset( $history[ $pk ] );
				continue;
			}
			// Cap indices per device: while a device stays active nothing else
			// prunes individual indices, so keep only the newest N by last_seen
			// (index keys preserved - audits look up history by index).
			if ( isset( $phone_data['indices'] ) && count( $phone_data['indices'] ) > self::MAX_INDICES_PER_PHONE ) {
				$indices = $phone_data['indices'];
				uasort( $indices, function ( $a, $b ) {
					return (int) ( $b['last_seen'] ?? 0 ) <=> (int) ( $a['last_seen'] ?? 0 );
				} );
				$history[ $pk ]['indices'] = array_slice( $indices, 0, self::MAX_INDICES_PER_PHONE, true );
			}
		}

		update_option( self::OPTION, $history, false );
	}

	/**
	 * Get the full address history.
	 */
	public static function get_history() {
		$history = get_option( self::OPTION, array() );
		if ( ! is_array( $history ) ) return array();
		return $history;
	}

	/**
	 * Get history for a specific device.
	 */
	public static function get_phone_history( $phone_pk ) {
		$history = self::get_history();
		return $history[ $phone_pk ] ?? null;
	}

	/**
	 * Clear all audit history.
	 */
	public static function clear() {
		delete_option( self::OPTION );
	}
}