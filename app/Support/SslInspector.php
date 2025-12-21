<?php

namespace App\Support;

use Carbon\Carbon;

class SslInspector
{
    /**
     * Return notAfter (expiry) for a hostname (port 443).
     * Null if unreachable or no cert.
     */
    public function getExpiry(string $host, int $port = 443): ?Carbon
    {
        $ctx = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'SNI_enabled'       => true,
                'SNI_server_name'   => $host,
                'crypto_method'     => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
            ],
        ]);

        $client = @stream_socket_client(
            "ssl://{$host}:{$port}",
            $errno,
            $errstr,
            8,
            STREAM_CLIENT_CONNECT,
            $ctx
        );
        
        if (!$client) {
            return null;
        }

        $params = stream_context_get_params($client);
        fclose($client);
        
        if (empty($params['options']['ssl']['peer_certificate'])) {
            return null;
        }

        $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
        
        if (!isset($cert['validTo_time_t'])) {
            return null;
        }

        return Carbon::createFromTimestamp((int)$cert['validTo_time_t'])->utc();
    }
}
