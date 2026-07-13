<?php

namespace App\Services;

use App\Models\Domain;
use App\Services\ScanReport\ScanRecommendationService;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;

class ScannerService
{
    public function scanDomain(string $domain): array
    {
        $records = [];
        $score = 0;
        $recommendations = [];
        $scoreBreakdown = [];

        try {
            Log::info('Starting domain scan', ['domain' => $domain]);

            // Check MX records
            $mxRecords = $this->safeDnsGetRecord($domain, DNS_MX, 'MX');
            $records['MX'] = !empty($mxRecords) ? ['status' => 'found', 'data' => $mxRecords] : ['status' => 'missing'];
            if (!empty($mxRecords)) {
                $score += (int) config('dns-scoring.mx.max', 15);
            }

            // Check SPF record (from TXT records)
            $txtRecords = $this->safeDnsGetRecord($domain, DNS_TXT, 'SPF TXT');
            $spfRecord = collect($txtRecords ?: [])->first(function ($record) {
                return isset($record['txt']) && str_contains($record['txt'], 'v=spf1');
            });
            
            $records['SPF'] = $spfRecord ? ['status' => 'found', 'data' => $spfRecord['txt']] : ['status' => 'missing'];
            
            if ($spfRecord) {
                $score += (int) config('dns-scoring.spf.base', 20);
            }

            // Check DKIM selectors (TXT records and CNAME-delegated setups)
            $dkimSelectors = config('dkim.selectors', []);
            $dkimFound = [];
            foreach ($dkimSelectors as $selector) {
                try {
                    $dkimDomain = "{$selector}._domainkey.{$domain}";

                    // First try TXT lookup (works for direct TXT and some CNAME chains)
                    $foundViaTxt = false;
                    $dkimRecords = $this->safeDnsGetRecord($dkimDomain, DNS_TXT, 'DKIM TXT');
                    if (!empty($dkimRecords)) {
                        foreach ($dkimRecords as $rec) {
                            if (isset($rec['txt']) && str_contains($rec['txt'], 'p=')) {
                                $dkimFound[] = [
                                    'selector' => $selector,
                                    'record' => $rec['txt'],
                                ];
                                $foundViaTxt = true;
                                break;
                            }
                        }
                    }

                    if ($foundViaTxt) {
                        continue; // found via TXT, skip CNAME check for this selector
                    }

                    // Fallback: check for CNAME (providers like Mandrill, SendGrid use CNAMEs)
                    $cnameRecords = $this->safeDnsGetRecord($dkimDomain, DNS_CNAME, 'DKIM CNAME');
                    if (!empty($cnameRecords)) {
                        $target = $cnameRecords[0]['target'] ?? '';
                        // Resolve the CNAME target for the actual TXT key
                        $targetTxt = $this->safeDnsGetRecord($target, DNS_TXT, 'DKIM CNAME target TXT');
                        $txtValue = '';
                        if (!empty($targetTxt)) {
                            foreach ($targetTxt as $rec) {
                                if (isset($rec['txt']) && str_contains($rec['txt'], 'p=')) {
                                    $txtValue = $rec['txt'];
                                    break;
                                }
                            }
                        }
                        $dkimFound[] = [
                            'selector' => $selector,
                            'record' => $txtValue ?: "CNAME → {$target}",
                            'type' => 'cname',
                            'target' => $target,
                        ];
                    }
                } catch (\Exception $e) {
                    // Skip failed selector lookups silently
                }
            }

            $records['DKIM'] = !empty($dkimFound)
                ? ['status' => 'found', 'data' => $dkimFound]
                : ['status' => 'missing'];

            if (!empty($dkimFound)) {
                $score += (int) config('dns-scoring.dkim.max', 20);
            }

            // Check DMARC record
            $dmarcRecords = $this->safeDnsGetRecord("_dmarc.$domain", DNS_TXT, 'DMARC TXT');
            $dmarcRecord = !empty($dmarcRecords) ? $dmarcRecords[0] : null;
            $records['DMARC'] = $dmarcRecord ? ['status' => 'found', 'data' => $dmarcRecord['txt']] : ['status' => 'missing'];
            
            if ($dmarcRecord) {
                $score += (int) config('dns-scoring.dmarc.base', 30);
            }

            // Check TLS-RPT record
            $tlsRptRecords = $this->safeDnsGetRecord("_smtp._tls.$domain", DNS_TXT, 'TLS-RPT TXT');
            $tlsRptRecord = !empty($tlsRptRecords) ? $tlsRptRecords[0] : null;
            $records['TLS-RPT'] = $tlsRptRecord ? ['status' => 'found', 'data' => $tlsRptRecord['txt']] : ['status' => 'missing'];
            
            if ($tlsRptRecord) {
                $score += (int) config('dns-scoring.tlsrpt.max', 5);
            }

            // Check MTA-STS record
            $mtaStsRecords = $this->safeDnsGetRecord("_mta-sts.$domain", DNS_TXT, 'MTA-STS TXT');
            $mtaStsRecord = !empty($mtaStsRecords) ? $mtaStsRecords[0] : null;
            $mtaStsPolicy = null;
            
            if ($mtaStsRecord) {
                // Try to fetch MTA-STS policy
                try {
                    $response = Http::timeout(5)->get("https://mta-sts.$domain/.well-known/mta-sts.txt");
                    if ($response->successful()) {
                        $mtaStsPolicy = $response->body();
                        $score += (int) config('dns-scoring.mtasts.full', 10);
                    } else {
                        $score += (int) config('dns-scoring.mtasts.dns_only', 5);
                    }
                } catch (\Exception $e) {
                    Log::info('MTA-STS policy not reachable', ['domain' => $domain, 'error' => $e->getMessage()]);
                    $score += (int) config('dns-scoring.mtasts.dns_only', 5);
                }
            }
            
            $records['MTA-STS'] = $mtaStsRecord ? 
                ['status' => 'found', 'data' => $mtaStsRecord['txt'], 'policy' => $mtaStsPolicy] : 
                ['status' => 'missing'];

            // BIMI check (informational only — never affects score)
            try {
                $bimiResult = app(BimiChecker::class)->check($domain);
                if ($bimiResult['record_found'] && $bimiResult['logo_valid']) {
                    $records['BIMI'] = ['status' => 'found', 'data' => $bimiResult];
                } elseif ($bimiResult['record_found']) {
                    $records['BIMI'] = ['status' => 'partial', 'data' => $bimiResult];
                } else {
                    $records['BIMI'] = ['status' => 'missing', 'data' => $bimiResult];
                }
            } catch (\Exception $e) {
                Log::warning('BIMI check failed', ['domain' => $domain, 'error' => $e->getMessage()]);
                $records['BIMI'] = ['status' => 'missing', 'data' => null];
            }

            // Cap score at 100
            $score = min($score, (int) config('dns-scoring.cap', 100));

            $scoreBreakdown = app(ScoreBreakdownService::class)->buildFromDnsRecords($records);

            $domainModel = Domain::query()->where('domain', $domain)->first()
                ?? new Domain(['domain' => $domain]);
            $recommendations = app(ScanRecommendationService::class)->build(
                $domainModel,
                ['dns' => ['records' => $records]],
                $records
            );

            Log::info('Domain scan completed', [
                'domain' => $domain,
                'score' => $score,
                'mx_found' => !empty($mxRecords),
                'spf_found' => !empty($spfRecord),
                'dkim_found' => !empty($dkimFound),
                'dkim_selectors' => array_column($dkimFound, 'selector'),
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
            'score_breakdown' => $scoreBreakdown ?? [],
        ];
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
            $records = $this->safeDnsGetRecord($domain, DNS_A, 'A');
            return !empty($records) ? $records[0]['ip'] : null;
        } catch (\Exception $e) {
            Log::warning("Failed to resolve IP for domain: $domain", ['error' => $e->getMessage()]);
            return null;
        }
    }

    private function safeDnsGetRecord(string $host, int $type, string $label): array
    {
        try {
            $records = @dns_get_record($host, $type);

            return is_array($records) ? $records : [];
        } catch (\Throwable $e) {
            Log::warning('DNS lookup failed', [
                'host' => $host,
                'record_type' => $label,
                'error' => $e->getMessage(),
            ]);

            return [];
        }
    }
}
