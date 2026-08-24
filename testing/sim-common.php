<?php
/**
 * OFFLINE sender-side simulation shared by the scanner verification harnesses.
 *
 * Builds a REALISTIC RingCT transaction exactly the way a Monero sender wallet does
 * (Zero-to-Monero §5.5 + wallet2.cpp, including the ge_mul8 that implementations apply
 * symmetrically on both sides), so a correct scanner MUST detect it with a matching
 * amount AND a passing commitment check - no node required.
 *
 * Deterministic keys → byte-identical tx across processes, so the enemy-plugin
 * reference scanner and the ported WC scanner can be compared output-for-output.
 */

if ( ! defined( 'XMR_SIM_LOADED' ) ) {
	define( 'XMR_SIM_LOADED', 1 );

	/** Fixed disposable test scalars (64-hex). NEVER use for real funds. */
	function xmr_sim_keys() {
		return array(
			'a' => '3b6765f2072e11438aaa22ae9168adf304c414d8da5de504dcdb46e397a6f604', // master private view
			'b' => '58b1c8d40b9c0a7e3f2d615a9c4e8b7d2f0a6c3e5d8b1f4a7c0e3d6b9a2c5f08', // primary spend secret (sim only)
			'r' => 'c0ffee00deadbeef1234567890abcdef01234567890abcdef0123456789abcde', // sender tx scalar
		);
	}

	/**
	 * Build one simulated payment tx.
	 *
	 * @param object $cn    MoneroIntegrations\MoneroPhp\Cryptonote instance.
	 * @param string $mode  'subaddress' (tag04 R'=r·D_s path) or 'standard' (main R=r·G path).
	 * @return array ['tx'=>..., 'address'=>..., 'amount_atomic'=>...]
	 */
	function xmr_sim_build_tx( $cn, $mode = 'subaddress' ) {
		if ( ! in_array( $mode, array( 'subaddress', 'standard' ), true ) ) {
			throw new Exception( "sim: unknown mode {$mode}" );
		}
		list( 'a' => $a_hex, 'b' => $b_hex, 'r' => $r_hex ) = xmr_sim_keys();
		// Reach the ed25519 instance whether the vendored Cryptonote exposes it
		// publicly (port's patched vendor) or keeps it protected (stock monerophp).
		if ( is_object( $cn->ed25519 ?? null ) ) {
			$ed = $cn->ed25519;
		} else {
			$ref = new ReflectionProperty( get_class( $cn ), 'ed25519' );
			if ( PHP_VERSION_ID < 80100 ) { $ref->setAccessible( true ); }
			$ed = $ref->getValue( $cn );
		}

		// Recipient address + its public keys.
		if ( 'subaddress' === $mode ) {
			$B     = $cn->pk_from_sk( $b_hex );
			$addr  = $cn->generate_subaddress( 0, 7, $a_hex, $B );   // order subaddress (0,7)
			$dec   = $cn->decode_address( $addr );
			$D_s   = strtolower( $dec['spendKey'] );
			$D_v   = strtolower( $dec['viewKey'] );
		} else {
			$B    = $cn->pk_from_sk( $b_hex );
			$addr = $cn->encode_address( $B, $cn->pk_from_sk( $a_hex ) );
			$dec  = $cn->decode_address( $addr );
			$D_s  = strtolower( $dec['spendKey'] );
			$D_v  = null; // standard outputs derive against A, not D_v
		}

		$r_int  = $ed->decodeint( hex2bin( $r_hex ) );
		$R_main = $cn->pk_from_sk( $r_hex ); // r·G

		// Sender derivation. Receiver computes gen_key_derivation(R_candidate, a):
		//   subaddress: receiver sees R'=r·D_s in tag04 → 8·a·R' = 8arD_s; sender: 8r·D_v = 8raD_s [ok] equal
		//   standard:   receiver uses main R=r·G            → 8arG;   sender: 8r·A              [ok] equal
		if ( 'subaddress' === $mode ) {
			$der_sender = $cn->gen_key_derivation( $D_v, $r_hex );
		} else {
			$der_sender = $cn->gen_key_derivation( strtolower( $dec['viewKey'] ), $r_hex ); // 8r·A
		}

		$i  = 0;
		$sk = $cn->derivation_to_scalar( $der_sender, $i );

		// One-time output key P_i = Hs(D,i)·G + recipient_spend_pub.
		$P = $cn->derive_public_key( $der_sender, $i, $D_s );

		// Encrypted amount (8 bytes little-endian XOR keccak("amount"||sk)).
		$amt        = '357000000000'; // 0.357 XMR atomic
		$amount_key = $cn->keccak_256( bin2hex( 'amount' ) . $sk );
		$be         = str_pad( gmp_strval( gmp_init( $amt, 10 ), 16 ), 16, '0', STR_PAD_LEFT );
		$le         = strrev( hex2bin( $be ) );
		$enc        = bin2hex( $le ^ substr( hex2bin( $amount_key ), 0, 8 ) );

		// Pedersen commitment C = mask·G + amt·H with the MONERO-CORRECT deterministic mask.
		$mask = $cn->hash_to_scalar( bin2hex( 'commitment_mask' ) . $sk );
		// Monero's fixed second generator H (generators.cpp): decode the constant
		// regardless of whether this vendored lib exposes get_H_point().
		$H = $ed->decodepoint( hex2bin( '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94' ) );
		$C    = bin2hex( $ed->encodepoint( $ed->edwards(
			$ed->scalarmult_base( $ed->decodeint( hex2bin( $mask ) ) ),
			$ed->scalarmult( $H, gmp_init( $amt, 10 ) )
		) ) );

		// extra: tag01 main R, tag02 nonce (length ≥128 exercises the varint path),
		// tag04 count=1 additional pubkey.
		$long_nonce  = str_repeat( '5a', 130 ); // 130 bytes → varint len = 0x82 0x01
		$extra_bytes = array_merge(
			array( 0x01 ),
			array_values( unpack( 'C*', hex2bin( $R_main ) ) ),
			array( 0x02, 0x82, 0x01 ),
			array_values( unpack( 'C*', hex2bin( $long_nonce ) ) )
		);
		if ( 'subaddress' === $mode ) {
			$R_sub       = bin2hex( $ed->encodepoint( $ed->scalarmult( $ed->decodepoint( hex2bin( $D_s ) ), $r_int ) ) ); // r·D_s, no mul8 on the pubkey itself
			$extra_bytes = array_merge( $extra_bytes, array( 0x04, 0x01 ), array_values( unpack( 'C*', hex2bin( $R_sub ) ) ) );
		}

		return array(
			'tx'            => array(
				'version'        => 2,
				'unlock_time'    => 0,
				'extra'          => $extra_bytes,
				'vout'           => array(
					array(
						'amount' => 0,
						'target' => array( 'tagged_key' => array( 'key' => $P ) ),
					),
				),
				'rct_signatures' => array(
					'ecdhInfo' => array( array( 'amount' => $enc ) ),
					'outPk'    => array( $C ),
				),
			),
			'address'       => $addr,
			'amount_atomic' => $amt,
		);
	}

	/** Run both scenarios through a callable scanner and print PASS/FAIL lines. */
	function xmr_sim_run( $label, $scanner ) {
		echo "== {$label} ==\n";
		$all_ok = true;
		foreach ( array( 'subaddress', 'standard' ) as $mode ) {
			$sim = xmr_sim_build_tx( $scanner['cn'], $mode );
			$m   = $scanner['detect']( $sim['tx'], $sim['address'], xmr_sim_keys()['a'] );
			$ok  = is_array( $m )
				&& isset( $m['commitment_ok'] ) && true === $m['commitment_ok']
				&& isset( $m['amount_atomic'] ) && $sim['amount_atomic'] === (string) $m['amount_atomic'];
			printf(
				"  %-11s detect=%s commitment_ok=%s amount=%s (expected %s) => %s\n",
				$mode,
				is_array( $m ) ? 'true' : 'false',
				is_array( $m ) && ! empty( $m['commitment_ok'] ) ? 'true' : 'false',
				is_array( $m ) ? $m['amount_atomic'] : '-',
				$sim['amount_atomic'],
				$ok ? 'PASS' : 'FAIL'
			);
			if ( ! $ok ) { $all_ok = false; }
		}
		return $all_ok;
	}
}
