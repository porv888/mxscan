<?php

namespace App\Services;

use App\Services\Dns\DnsClient;
use Illuminate\Support\Facades\Log;

class SmtpTester
{
    private DnsClient $dnsClient;

    public function __construct(DnsClient $dnsClient)
    {
        $this->dnsClient = $dnsClient;
    }

    /**
     * Test SMTP connectivity for a domain.
     * Resolves MX records, connects to each, checks banner and STARTTLS.
     */
    public function test(string $domain, int $port = 25, int $timeout = 5): array
    {
        $results = [];
        $mxHosts = $this->dnsClient->getMx($domain);

        if (empty($mxHosts)) {
            // Fallback to A record (domain itself as mail server)
            $mxHosts = [$domain];
        }

        foreach ($mxHosts as $host) {
            $results[] = $this->testHost($host, $port, $timeout);
        }

        return [
            'domain' => $domain,
            'port' => $port,
            'mx_hosts' => $mxHosts,
            'results' => $results,
            'tested_at' => now()->toISOString(),
        ];
    }

    /**
     * Test a single SMTP host.
     */
    private function testHost(string $host, int $port, int $timeout): array
    {
        $result = [
            'host' => $host,
            'port' => $port,
            'connectable' => false,
            'banner' => null,
            'ehlo_response' => null,
            'starttls' => false,
            'tls_version' => null,
            'response_time_ms' => null,
            'error' => null,
        ];

        $startTime = microtime(true);

        try {
            $errno = 0;
            $errstr = '';
            $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);

            if (!$socket) {
                $result['error'] = "Connection failed: {$errstr} (errno: {$errno})";
                $result['response_time_ms'] = round((microtime(true) - $startTime) * 1000);
                return $result;
            }

            stream_set_timeout($socket, $timeout);
            $result['connectable'] = true;

            // Read banner (220 greeting)
            $banner = $this->readLine($socket);
            $result['banner'] = trim($banner);

            // Send EHLO
            fwrite($socket, "EHLO mxscan.me\r\n");
            $ehloResponse = $this->readMultiLine($socket);
            $result['ehlo_response'] = $ehloResponse;

            // Check for STARTTLS support
            $result['starttls'] = $this->supportsStartTls($ehloResponse);

            if ($result['starttls']) {
                // Attempt STARTTLS
                fwrite($socket, "STARTTLS\r\n");
                $tlsResponse = $this->readLine($socket);

                if (str_starts_with(trim($tlsResponse), '220')) {
                    // Upgrade to TLS
                    $tlsResult = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
                    if ($tlsResult) {
                        $meta = stream_get_meta_data($socket);
                        $cryptoInfo = $meta['crypto'] ?? [];
                        $result['tls_version'] = $cryptoInfo['protocol'] ?? 'TLS (version unknown)';
                    } else {
                        $result['tls_version'] = 'STARTTLS offered but upgrade failed';
                    }
                }
            }

            // Send QUIT
            fwrite($socket, "QUIT\r\n");
            fclose($socket);

            $result['response_time_ms'] = round((microtime(true) - $startTime) * 1000);

        } catch (\Exception $e) {
            $result['error'] = $e->getMessage();
            $result['response_time_ms'] = round((microtime(true) - $startTime) * 1000);
            Log::warning("SMTP test failed for {$host}:{$port}: " . $e->getMessage());
        }

        return $result;
    }

    /**
     * Read a single line from the socket.
     */
    private function readLine($socket): string
    {
        $line = @fgets($socket, 512);
        return $line !== false ? $line : '';
    }

    /**
     * Read a multi-line SMTP response (continuation lines have - after code).
     */
    private function readMultiLine($socket): string
    {
        $response = '';
        $maxLines = 50;
        $count = 0;

        while ($count < $maxLines) {
            $line = @fgets($socket, 512);
            if ($line === false) {
                break;
            }
            $response .= $line;
            $count++;

            // Check if this is the last line (no hyphen after status code)
            if (preg_match('/^\d{3} /', $line)) {
                break;
            }
        }

        return trim($response);
    }

    /**
     * Check if EHLO response indicates STARTTLS support.
     */
    private function supportsStartTls(string $ehloResponse): bool
    {
        return (bool) preg_match('/250[- ]STARTTLS/i', $ehloResponse);
    }
}
