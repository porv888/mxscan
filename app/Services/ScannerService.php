<?php

namespace App\Services;

use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcTxtReconstructor;
use App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsTxtReconstructor;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiTxtReconstructor;
use App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptTxtReconstructor;
use App\Models\Domain;
use App\Services\ScanReport\ScanRecommendationService;
use Illuminate\Support\Facades\Log;

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

            // MX analysis is handled by native MxCheck
            $txtRecords = $this->safeDnsGetRecord($domain, DNS_TXT, 'SPF TXT');
            $rootTxtRecords = [];
            foreach ($txtRecords ?: [] as $record) {
                if (!isset($record['txt'])) {
                    continue;
                }
                $rootTxtRecords[] = [
                    'host' => $record['host'] ?? $domain,
                    'txt' => $record['txt'],
                    'ttl' => $record['ttl'] ?? null,
                ];
            }
            $spfRecord = collect($txtRecords ?: [])->first(function ($record) {
                return isset($record['txt']) && $this->txtContainsSpfVersion($record['txt']);
            });

            $records['SPF'] = $spfRecord ? ['status' => 'found', 'data' => $spfRecord['txt']] : ['status' => 'missing'];
            
            if ($spfRecord) {
                $score += (int) config('dns-scoring.spf.base', 20);
            }

            // Collect DMARC TXT evidence (scoring handled by native DmarcScoreRule)
            $dmarcHostname = "_dmarc.$domain";
            $dmarcRecords = $this->safeDnsGetRecord($dmarcHostname, DNS_TXT, 'DMARC TXT');
            $dmarcTxtRecords = [];
            foreach ($dmarcRecords ?: [] as $index => $record) {
                $joined = DmarcTxtReconstructor::fromDnsRow($record);
                if ($joined === null) {
                    continue;
                }
                $dmarcTxtRecords[] = [
                    'host' => $dmarcHostname,
                    'txt' => $joined,
                    'ttl' => $record['ttl'] ?? null,
                    'rr_index' => $index,
                ];
            }
            $dmarcMatches = DmarcTxtReconstructor::selectDmarcRecords(
                array_column($dmarcTxtRecords, 'txt'),
            );
            $dmarcRecord = $dmarcMatches[0] ?? null;
            $records['DMARC'] = $dmarcRecord
                ? ['status' => 'found', 'data' => $dmarcRecord]
                : ['status' => 'missing'];

            // Collect TLS-RPT TXT evidence (analysis handled by native TlsRptCheck)
            $tlsRptHostname = "_smtp._tls.$domain";
            $tlsRptRecords = $this->safeDnsGetRecord($tlsRptHostname, DNS_TXT, 'TLS-RPT TXT');
            $tlsRptTxtRecords = [];
            foreach ($tlsRptRecords ?: [] as $index => $record) {
                $joined = TlsRptTxtReconstructor::fromDnsRow($record);
                if ($joined === null) {
                    continue;
                }
                $tlsRptTxtRecords[] = [
                    'host' => $tlsRptHostname,
                    'txt' => $joined,
                    'ttl' => $record['ttl'] ?? null,
                    'rr_index' => $index,
                ];
            }
            $tlsRptMatches = TlsRptTxtReconstructor::selectTlsRptRecords(
                array_column($tlsRptTxtRecords, 'txt'),
            );
            $tlsRptRecord = $tlsRptMatches[0] ?? null;
            $records['TLS-RPT'] = $tlsRptRecord
                ? ['status' => 'found', 'data' => $tlsRptRecord]
                : ['status' => 'missing'];

            // Collect MTA-STS TXT evidence (analysis handled by native MtaStsCheck)
            $mtaStsHostname = "_mta-sts.$domain";
            $mtaStsRecords = $this->safeDnsGetRecord($mtaStsHostname, DNS_TXT, 'MTA-STS TXT');
            $mtaStsTxtRecords = [];
            foreach ($mtaStsRecords ?: [] as $index => $record) {
                $joined = MtaStsTxtReconstructor::fromDnsRow($record);
                if ($joined === null) {
                    continue;
                }
                $mtaStsTxtRecords[] = [
                    'host' => $mtaStsHostname,
                    'txt' => $joined,
                    'ttl' => $record['ttl'] ?? null,
                    'rr_index' => $index,
                ];
            }
            $mtaStsMatches = MtaStsTxtReconstructor::selectIndicatorRecords(
                array_column($mtaStsTxtRecords, 'txt'),
            );
            $mtaStsRecord = $mtaStsMatches[0] ?? null;
            $records['MTA-STS'] = $mtaStsRecord
                ? ['status' => 'found', 'data' => $mtaStsRecord]
                : ['status' => 'missing'];

            // Collect BIMI TXT evidence at default selector (analysis handled by native BimiCheck)
            $bimiHostname = "default._bimi.$domain";
            $bimiRecords = $this->safeDnsGetRecord($bimiHostname, DNS_TXT, 'BIMI TXT');
            $bimiTxtRecords = [];
            foreach ($bimiRecords ?: [] as $index => $record) {
                $joined = BimiTxtReconstructor::fromDnsRow($record);
                if ($joined === null) {
                    continue;
                }
                $bimiTxtRecords[] = [
                    'host' => $bimiHostname,
                    'txt' => $joined,
                    'ttl' => $record['ttl'] ?? null,
                    'rr_index' => $index,
                ];
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
            'score_breakdown' => $scoreBreakdown ?? [],
            'root_txt_records' => $rootTxtRecords ?? [],
            'dmarc_txt_records' => $dmarcTxtRecords ?? [],
            'mta_sts_txt_records' => $mtaStsTxtRecords ?? [],
            'tls_rpt_txt_records' => $tlsRptTxtRecords ?? [],
            'bimi_txt_records' => $bimiTxtRecords ?? [],
        ];
    }

    /**
     * @param string|list<string> $txt
     */
    private function txtContainsSpfVersion(string|array $txt): bool
    {
        $value = is_array($txt) ? implode('', $txt) : $txt;

        return stripos($value, 'v=spf1') !== false;
    }

    /**
     * Generate an appropriate SPF record based on the domain's MX records
     */
    private function generateSpfRecord(string $domain, array $records): string
    {
        $domainIp = $this->getDomainIp($domain);

        return $domainIp ? "v=spf1 ip4:$domainIp a mx -all" : "v=spf1 a mx -all";
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
