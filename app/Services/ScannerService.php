<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;

class ScannerService
{
    public function scanDomain(string $domain): array
    {
        $records = [];
        $score = 0;
        $recommendations = [];

        try {
            Log::info('Starting domain scan', ['domain' => $domain]);

            // Check MX records
            $mxRecords = dns_get_record($domain, DNS_MX);
            $records['MX'] = !empty($mxRecords) ? ['status' => 'found', 'data' => $mxRecords] : ['status' => 'missing'];
            if (!empty($mxRecords)) {
                $score += 20;
            }

            // Check SPF record (from TXT records)
            $txtRecords = dns_get_record($domain, DNS_TXT);
            $spfRecord = collect($txtRecords ?: [])->first(function ($record) {
                return isset($record['txt']) && str_contains($record['txt'], 'v=spf1');
            });
            
            $records['SPF'] = $spfRecord ? ['status' => 'found', 'data' => $spfRecord['txt']] : ['status' => 'missing'];
            
            if ($spfRecord) {
                $score += 20;
                // Bonus points for strict SPF
                if (str_contains($spfRecord['txt'], '-all')) {
                    $score += 5;
                } elseif (str_contains($spfRecord['txt'], '~all')) {
                    $score += 2;
                }
            }

            // Check DMARC record
            $dmarcRecords = dns_get_record("_dmarc.$domain", DNS_TXT);
            $dmarcRecord = !empty($dmarcRecords) ? $dmarcRecords[0] : null;
            $records['DMARC'] = $dmarcRecord ? ['status' => 'found', 'data' => $dmarcRecord['txt']] : ['status' => 'missing'];
            
            if ($dmarcRecord) {
                $score += 20;
                // Bonus points for strict DMARC policy
                if (str_contains($dmarcRecord['txt'], 'p=reject')) {
                    $score += 5;
                } elseif (str_contains($dmarcRecord['txt'], 'p=quarantine')) {
                    $score += 3;
                }
            }

            // Check TLS-RPT record
            $tlsRptRecords = dns_get_record("_smtp._tls.$domain", DNS_TXT);
            $tlsRptRecord = !empty($tlsRptRecords) ? $tlsRptRecords[0] : null;
            $records['TLS-RPT'] = $tlsRptRecord ? ['status' => 'found', 'data' => $tlsRptRecord['txt']] : ['status' => 'missing'];
            
            if ($tlsRptRecord) {
                $score += 15;
            }

            // Check MTA-STS record
            $mtaStsRecords = dns_get_record("_mta-sts.$domain", DNS_TXT);
            $mtaStsRecord = !empty($mtaStsRecords) ? $mtaStsRecords[0] : null;
            $mtaStsPolicy = null;
            
            if ($mtaStsRecord) {
                // Try to fetch MTA-STS policy
                try {
                    $response = Http::timeout(5)->get("https://mta-sts.$domain/.well-known/mta-sts.txt");
                    if ($response->successful()) {
                        $mtaStsPolicy = $response->body();
                        $score += 20; // Full points for working MTA-STS
                    } else {
                        $score += 10; // Partial points for DNS record only
                    }
                } catch (\Exception $e) {
                    Log::warning('MTA-STS policy fetch failed', ['domain' => $domain, 'error' => $e->getMessage()]);
                    $score += 10; // Partial points for DNS record only
                }
            }
            
            $records['MTA-STS'] = $mtaStsRecord ? 
                ['status' => 'found', 'data' => $mtaStsRecord['txt'], 'policy' => $mtaStsPolicy] : 
                ['status' => 'missing'];

            // Cap score at 100
            $score = min($score, 100);

            // Generate recommendations based on actual DNS results
            $recommendations = $this->generateRecommendations($domain, $records);

            Log::info('Domain scan completed', [
                'domain' => $domain,
                'score' => $score,
                'mx_found' => !empty($mxRecords),
                'spf_found' => !empty($spfRecord),
                'dmarc_found' => !empty($dmarcRecord),
                'tlsrpt_found' => !empty($tlsRptRecord),
                'mtasts_found' => !empty($mtaStsRecord),
                'recommendations_count' => count($recommendations)
            ]);

        } catch (\Exception $e) {
            Log::error('Scan failed', ['domain' => $domain, 'error' => $e->getMessage()]);
            throw $e;
        }

        return [
            'score' => $score,
            'records' => $records,
            'recommendations' => $recommendations,
        ];
    }

    private function generateRecommendations(string $domain, array $records): array
    {
        $recommendations = [];

        if ($records['MX']['status'] === 'missing') {
            $recommendations[] = [
                'type' => 'MX',
                'title' => 'Add MX record',
                'value' => "10 mail.$domain",
                'description' => 'MX records tell other mail servers where to deliver email for your domain.',
            ];
        }

        if ($records['SPF']['status'] === 'missing') {
            $spfValue = $this->generateSpfRecord($domain, $records);
            $recommendations[] = [
                'type' => 'SPF',
                'title' => 'Add SPF record',
                'value' => $spfValue,
                'description' => 'SPF records prevent email spoofing by specifying which servers can send email for your domain.',
            ];
        }

        if ($records['DMARC']['status'] === 'missing') {
            $recommendations[] = [
                'type' => 'DMARC',
                'title' => 'Add DMARC record',
                'value' => "v=DMARC1; p=quarantine; rua=mailto:dmarc@$domain",
                'description' => 'DMARC policies tell receiving servers what to do with emails that fail SPF/DKIM checks.',
            ];
        }

        if ($records['TLS-RPT']['status'] === 'missing') {
            $recommendations[] = [
                'type' => 'TLS-RPT',
                'title' => 'Add TLS-RPT record',
                'value' => "v=TLSRPTv1; rua=mailto:reports@$domain",
                'description' => 'TLS-RPT records enable reporting of TLS connection failures for your domain.',
            ];
        }

        if ($records['MTA-STS']['status'] === 'missing') {
            $recommendations[] = [
                'type' => 'MTA-STS',
                'title' => 'Add MTA-STS record',
                'value' => 'v=STSv1; id=20250910',
                'description' => 'MTA-STS enforces secure TLS connections for email delivery to your domain.',
            ];
        }

        return $recommendations;
    }

    /**
     * Generate an appropriate SPF record based on the domain's MX records
     */
    private function generateSpfRecord(string $domain, array $records): string
    {
        // If no MX records, suggest a basic SPF record with domain IP
        if ($records['MX']['status'] === 'missing') {
            $domainIp = $this->getDomainIp($domain);
            return $domainIp ? "v=spf1 ip4:$domainIp a mx -all" : "v=spf1 a mx -all";
        }

        $mxRecords = $records['MX']['data'] ?? [];
        $spfMechanisms = ['v=spf1'];
        $addedMechanisms = [];

        // Get domain IP for potential inclusion
        $domainIp = $this->getDomainIp($domain);
        if ($domainIp && !in_array("ip4:$domainIp", $addedMechanisms)) {
            $spfMechanisms[] = "ip4:$domainIp";
            $addedMechanisms[] = "ip4:$domainIp";
        }

        foreach ($mxRecords as $mx) {
            $mailServer = rtrim($mx['target'], '.');
            
            // Detect common email providers and suggest appropriate includes
            if (str_contains($mailServer, 'google.com') || str_contains($mailServer, 'googlemail.com')) {
                if (!in_array('include:_spf.google.com', $addedMechanisms)) {
                    $spfMechanisms[] = 'include:_spf.google.com';
                    $addedMechanisms[] = 'include:_spf.google.com';
                }
            } elseif (str_contains($mailServer, 'outlook.com') || str_contains($mailServer, 'office365.com')) {
                if (!in_array('include:spf.protection.outlook.com', $addedMechanisms)) {
                    $spfMechanisms[] = 'include:spf.protection.outlook.com';
                    $addedMechanisms[] = 'include:spf.protection.outlook.com';
                }
            } elseif (str_contains($mailServer, 'mailgun.org')) {
                if (!in_array('include:mailgun.org', $addedMechanisms)) {
                    $spfMechanisms[] = 'include:mailgun.org';
                    $addedMechanisms[] = 'include:mailgun.org';
                }
            } elseif (str_contains($mailServer, 'sendgrid.net')) {
                if (!in_array('include:sendgrid.net', $addedMechanisms)) {
                    $spfMechanisms[] = 'include:sendgrid.net';
                    $addedMechanisms[] = 'include:sendgrid.net';
                }
            } else {
                // For custom mail servers, get their IP and add both mechanisms
                $mailServerIp = $this->getDomainIp($mailServer);
                if ($mailServerIp && !in_array("ip4:$mailServerIp", $addedMechanisms)) {
                    // Only add if different from domain IP
                    if ($mailServerIp !== $domainIp) {
                        $spfMechanisms[] = "ip4:$mailServerIp";
                        $addedMechanisms[] = "ip4:$mailServerIp";
                    }
                }
                
                // Add 'a' mechanism for mail servers under same domain
                if (str_contains($mailServer, $domain) && !in_array('a', $addedMechanisms)) {
                    $spfMechanisms[] = 'a';
                    $addedMechanisms[] = 'a';
                }
                
                // Add mx mechanism
                if (!in_array('mx', $addedMechanisms)) {
                    $spfMechanisms[] = 'mx';
                    $addedMechanisms[] = 'mx';
                }
            }
        }

        // Add strict policy
        $spfMechanisms[] = '-all';

        return implode(' ', $spfMechanisms);
    }

    /**
     * Get the IP address of a domain
     */
    private function getDomainIp(string $domain): ?string
    {
        try {
            $records = dns_get_record($domain, DNS_A);
            return !empty($records) ? $records[0]['ip'] : null;
        } catch (Exception $e) {
            Log::warning("Failed to resolve IP for domain: $domain", ['error' => $e->getMessage()]);
            return null;
        }
    }
}
