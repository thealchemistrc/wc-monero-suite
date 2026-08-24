<?php
/**
 * Probe for monero-wallet-rpc and get address + view key.
 * Tries common ports: 28012, 28082, 28083, 18082
 */

$ports = [28012, 28082, 28083, 18082, 28090, 28091];

foreach ($ports as $port) {
    $url = "http://127.0.0.1:$port/json_rpc";
    echo "Trying port $port... ";

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode([
            'jsonrpc' => '2.0',
            'id' => '0',
            'method' => 'get_address',
            'params' => ['account_index' => 0],
        ]),
        CURLOPT_TIMEOUT => 3,
        CURLOPT_CONNECTTIMEOUT => 2,
    ]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($err) {
        echo "FAIL ($err)\n";
        continue;
    }
    if ($code !== 200) {
        echo "HTTP $code\n";
        // Maybe needs auth - try with digest
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_POSTFIELDS => json_encode([
                'jsonrpc' => '2.0',
                'id' => '0',
                'method' => 'get_address',
                'params' => ['account_index' => 0],
            ]),
            CURLOPT_TIMEOUT => 3,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_HTTPAUTH => CURLAUTH_DIGEST | CURLAUTH_BASIC,
            CURLOPT_USERPWD => 'test:test',
        ]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($code === 200 && $resp) {
            echo "OK with auth!\n";
            echo $resp . "\n";
            // Now get view key
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
                CURLOPT_POSTFIELDS => json_encode([
                    'jsonrpc' => '2.0',
                    'id' => '0',
                    'method' => 'query_key',
                    'params' => ['key_type' => 'view_key'],
                ]),
                CURLOPT_TIMEOUT => 3,
                CURLOPT_HTTPAUTH => CURLAUTH_DIGEST | CURLAUTH_BASIC,
                CURLOPT_USERPWD => 'test:test',
            ]);
            $resp2 = curl_exec($ch);
            curl_close($ch);
            echo "View key: $resp2\n";
            break;
        }
        echo "Auth also failed: $err\n";
        continue;
    }

    echo "OK!\n";
    echo $resp . "\n";

    // Get view key
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode([
            'jsonrpc' => '2.0',
            'id' => '0',
            'method' => 'query_key',
            'params' => ['key_type' => 'view_key'],
        ]),
        CURLOPT_TIMEOUT => 3,
    ]);
    $resp2 = curl_exec($ch);
    curl_close($ch);
    echo "View key: $resp2\n";
    break;
}

echo "\nDone.\n";