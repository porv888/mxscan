<?php

namespace App\Domain\EmailSecurity\Recommendations;

use App\Domain\EmailSecurity\Checks\SPF\Recommendations\SpfRecommendationEvaluator;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Models\Domain;

/**
 * Single source of truth for ordered scan recommendations.
 */
class ScanRecommendationService
{
    public function __construct(
        protected ScanReportStatusMapper $mapper = new ScanReportStatusMapper(),
        protected SpfRecommendationEvaluator $spfRecommendationEvaluator = new SpfRecommendationEvaluator(),
    ) {
    }

    /**
     * @param array<string, mixed> $resultJson Full result_json (dns/spf/blacklist)
     * @param array<string, mixed>|null $records Override dns.records if already extracted
     * @return list<array<string, mixed>>
     */
    public function build(Domain $domain, array $resultJson, ?array $records = null): array
    {
        $records = $records ?? ($resultJson['dns']['records'] ?? []);
        $spfInfo = $resultJson['spf'] ?? null;
        $blacklist = $resultJson['blacklist'] ?? null;
        $items = [];

        $blacklistCard = $this->mapper->mapBlacklist($blacklist);
        if ($blacklistCard['state'] === ScanReportStatusMapper::FAIL) {
            $listed = (int) ($blacklist['listed_count'] ?? 0);
            $items[] = $this->item(
                'blacklist',
                1,
                'critical',
                'Remove from Blacklists',
                "Your mail servers are listed on {$listed} blacklist(s). This severely impacts email delivery trust.",
                'View delist links',
                null,
                null,
                ScanReportStatusMapper::FAIL
            );
        }

        $dmarc = $records['DMARC'] ?? null;
        $dmarcPolicy = null;
        if (($dmarc['status'] ?? '') === 'found' && is_string($dmarc['data'] ?? null)) {
            if (preg_match('/p=([^;]+)/i', $dmarc['data'], $m)) {
                $dmarcPolicy = trim($m[1]);
            }
        }

        if (($dmarc['status'] ?? '') !== 'found') {
            $items[] = $this->item(
                'dmarc_missing',
                2,
                'high',
                'Add DMARC Policy',
                'DMARC protects your domain from email spoofing and phishing attacks.',
                'Add DMARC record',
                '_dmarc.' . $domain->domain,
                'v=DMARC1; p=quarantine; rua=mailto:' . $this->ruaAddress($domain) . '; pct=100; adkim=r; aspf=r;',
                ScanReportStatusMapper::MISSING
            );
        } elseif ($dmarcPolicy === 'none') {
            $items[] = $this->item(
                'dmarc_policy',
                3,
                'high',
                'Upgrade DMARC Policy',
                'Your DMARC policy is set to "none" which provides monitoring only. Upgrade to quarantine or reject.',
                'Upgrade to quarantine',
                '_dmarc.' . $domain->domain,
                'v=DMARC1; p=quarantine; rua=mailto:' . $this->ruaAddress($domain) . '; pct=100; adkim=r; aspf=r;',
                ScanReportStatusMapper::WARNING
            );
        } elseif (is_string($dmarc['data'] ?? null)) {
            $dmarcTxt = $dmarc['data'];
            $hasAlignmentTags = str_contains($dmarcTxt, 'aspf=') || str_contains($dmarcTxt, 'adkim=');
            if (!$hasAlignmentTags) {
                $suggested = rtrim($dmarcTxt, " ;\t") . '; adkim=r; aspf=r';
                $items[] = $this->item(
                    'dmarc_alignment',
                    3,
                    'high',
                    'Add DMARC Alignment Tags',
                    'Your DMARC record is missing aspf/adkim tags. This is DNS-tag configuration only — not proof of live header alignment.',
                    'Add aspf/adkim',
                    '_dmarc.' . $domain->domain,
                    $suggested,
                    ScanReportStatusMapper::WARNING
                );
            }
        }

        $spfRecord = $records['SPF'] ?? null;
        $spfCard = $this->mapper->mapSpf($spfRecord, $spfInfo);

        foreach ($this->spfRecommendationEvaluator->evaluate($spfRecord, $spfCard, $spfInfo) as $spfItem) {
            $priority = match ($spfItem['legacy_key']) {
                'spf_missing', 'spf_invalid' => 4,
                default => 5,
            };
            $items[] = $this->item(
                $spfItem['legacy_key'],
                $priority,
                $spfItem['severity'],
                $spfItem['title'],
                $spfItem['body'],
                $spfItem['legacy_key'] === 'spf_missing' ? 'Add SPF' : ($spfItem['legacy_key'] === 'spf_invalid' ? 'Fix SPF' : 'Flatten SPF'),
                $spfItem['legacy_key'] === 'spf_lookups' ? $domain->domain : $domain->domain,
                $spfItem['suggested'],
                $spfItem['card_state'],
            );
        }

        $dkim = $records['DKIM'] ?? null;
        if (($dkim['status'] ?? '') !== 'found') {
            $items[] = $this->item(
                'dkim_dns',
                6,
                'high',
                'Add DKIM DNS Configuration',
                'Publish DKIM selector DNS records with your mail provider. This confirms DNS keys only — live signing requires header or DMARC-report evidence.',
                'Configure DKIM DNS',
                null,
                null,
                ScanReportStatusMapper::MISSING
            );
        }

        if (($records['TLS-RPT']['status'] ?? '') !== 'found') {
            $items[] = $this->item(
                'tlsrpt',
                7,
                'low',
                'Add TLS-RPT Record',
                'Get reports about TLS connection failures to your mail servers.',
                'Add TLS-RPT',
                '_smtp._tls.' . $domain->domain,
                'v=TLSRPTv1; rua=mailto:tlsrpt@' . $domain->domain,
                ScanReportStatusMapper::MISSING
            );
        }

        if (($records['MTA-STS']['status'] ?? '') !== 'found') {
            $items[] = $this->item(
                'mtasts',
                8,
                'low',
                'Add MTA-STS Policy',
                'Enforce TLS encryption for incoming email connections.',
                'Add MTA-STS',
                '_mta-sts.' . $domain->domain,
                'v=STSv1; id=' . date('Ymd') . '01',
                ScanReportStatusMapper::MISSING
            );
        }

        $bimiStatus = $records['BIMI']['status'] ?? 'missing';
        if ($bimiStatus !== 'found') {
            $items[] = $this->item(
                'bimi',
                9,
                'optional',
                'Optional: Add BIMI',
                'BIMI is an optional branding feature and does not affect Email Security Score.',
                'Learn about BIMI',
                'default._bimi.' . $domain->domain,
                null,
                ScanReportStatusMapper::NOT_APPLICABLE
            );
        }

        usort($items, fn ($a, $b) => $a['priority'] <=> $b['priority']);

        return $items;
    }

    /**
     * @param array<string, mixed> $resultJson
     * @return array{state: string, message: string|null}
     */
    public function evaluateAllClear(array $resultJson, ?array $records = null): array
    {
        $records = $records ?? ($resultJson['dns']['records'] ?? []);
        $spfInfo = $resultJson['spf'] ?? null;
        $blacklist = $resultJson['blacklist'] ?? null;

        $mxOk = ($records['MX']['status'] ?? '') === 'found';
        $spfCard = $this->mapper->mapSpf($records['SPF'] ?? null, $spfInfo);
        $dkimCard = $this->mapper->mapDkim($records['DKIM'] ?? null);
        $dmarcCard = $this->mapper->mapDmarc($records['DMARC'] ?? null);
        $blacklistCard = $this->mapper->mapBlacklist($blacklist);

        $spfOk = $spfCard['state'] === ScanReportStatusMapper::PASS
            || $spfCard['state'] === ScanReportStatusMapper::WARNING;
        // Warning (near limit) still "present and valid" for all-clear core auth,
        // but fail threshold (>=10) blocks. Plan: lookups checked and below failure threshold.
        if ($spfCard['state'] === ScanReportStatusMapper::WARNING) {
            $spfOk = true; // below failure (<10)
        }
        if ($spfCard['state'] === ScanReportStatusMapper::FAIL) {
            $spfOk = false;
        }
        if ($spfCard['state'] === ScanReportStatusMapper::NOT_CHECKED) {
            $spfOk = false;
        }

        $dkimOk = $dkimCard['state'] === ScanReportStatusMapper::PASS && ($dkimCard['count'] ?? 0) >= 1;
        $dmarcOk = ($records['DMARC']['status'] ?? '') === 'found'
            && ($dmarcCard['policy'] ?? null) !== 'none';

        $coreOk = $mxOk && $spfOk && $dkimOk && $dmarcOk;

        if (!$coreOk) {
            return [
                'state' => 'needs_fixes',
                'message' => null,
            ];
        }

        if ($blacklistCard['state'] === ScanReportStatusMapper::NOT_CHECKED) {
            return [
                'state' => 'partial_clear',
                'message' => 'Core DNS authentication checks passed; blacklist status was not checked.',
            ];
        }

        if ($blacklistCard['state'] === ScanReportStatusMapper::FAIL) {
            return [
                'state' => 'needs_fixes',
                'message' => null,
            ];
        }

        return [
            'state' => 'all_clear',
            'message' => 'No critical fixes needed. Core email authentication checks passed.',
        ];
    }

    protected function ruaAddress(Domain $domain): string
    {
        if ($domain->exists) {
            return $domain->dmarc_rua_email;
        }

        return 'dmarc@' . $domain->domain;
    }

    /**
     * @return array<string, mixed>
     */
    protected function item(
        string $key,
        int $priority,
        string $severity,
        string $title,
        string $explanation,
        ?string $action,
        ?string $recordName,
        ?string $value,
        string $state
    ): array {
        return [
            'key' => $key,
            'priority' => $priority,
            'severity' => $severity,
            'title' => $title,
            'explanation' => $explanation,
            'action' => $action,
            'record_name' => $recordName,
            'value' => $value,
            'state' => $state,
        ];
    }
}
