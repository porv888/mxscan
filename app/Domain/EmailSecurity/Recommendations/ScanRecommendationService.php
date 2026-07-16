<?php

namespace App\Domain\EmailSecurity\Recommendations;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\BimiRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\Blacklist\Recommendations\BlacklistRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\DKIM\Recommendations\DkimRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimAnalysisReader;
use App\Domain\EmailSecurity\Checks\DMARC\Recommendations\DmarcRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcAlignmentVerification;
use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcAnalysisReader;
use App\Domain\EmailSecurity\Checks\MtaSts\Recommendations\MtaStsRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\Mx\Recommendations\MxRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader;
use App\Domain\EmailSecurity\Checks\Certificates\Recommendations\CertificateRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Domain\EmailSecurity\Checks\Mx\MxRiskStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;
use App\Domain\EmailSecurity\Checks\TlsRpt\Recommendations\TlsRptRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\SPF\Recommendations\SpfRecommendationEvaluator;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Models\Domain;

/**
 * Single source of truth for ordered scan recommendations.
 */
class ScanRecommendationService
{
    public function __construct(
        protected ScanReportStatusMapper $mapper,
        protected SpfRecommendationEvaluator $spfRecommendationEvaluator,
        protected DmarcRecommendationEvaluator $dmarcRecommendationEvaluator,
        protected DkimRecommendationEvaluator $dkimRecommendationEvaluator,
        protected MtaStsRecommendationEvaluator $mtaStsRecommendationEvaluator,
        protected MxRecommendationEvaluator $mxRecommendationEvaluator,
        protected TlsRptRecommendationEvaluator $tlsRptRecommendationEvaluator,
        protected CertificateRecommendationEvaluator $certificateRecommendationEvaluator,
        protected BimiRecommendationEvaluator $bimiRecommendationEvaluator,
        protected BlacklistRecommendationEvaluator $blacklistRecommendationEvaluator,
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
        foreach ($this->blacklistRecommendationEvaluator->evaluate($blacklist, $blacklistCard) as $blItem) {
            $items[] = $this->item(
                semanticKey: $blItem['semantic_key'],
                legacyKey: $blItem['legacy_key'],
                priority: $blItem['semantic_key'] === 'investigate_blacklist_listing' ? 1 : 2,
                severity: $blItem['severity'],
                title: $blItem['title'],
                explanation: $blItem['body'],
                action: $blItem['semantic_key'] === 'request_blacklist_delisting' ? 'View delist links' : $blItem['title'],
                recordName: null,
                value: null,
                state: $blItem['card_state'],
            );
        }

        $dmarc = $records['DMARC'] ?? null;
        $dmarcInfo = $resultJson['dmarc'] ?? null;
        $dmarcCard = $this->mapper->mapDmarc($dmarc, $dmarcInfo);

        foreach ($this->dmarcRecommendationEvaluator->evaluate($domain, $dmarcCard, $dmarcInfo) as $dmarcItem) {
            $priority = match ($dmarcItem['legacy_key']) {
                'dmarc_missing', 'dmarc_invalid' => 2,
                'dmarc_policy', 'dmarc_pct' => 3,
                default => 4,
            };
            $items[] = $this->item(
                semanticKey: $dmarcItem['semantic_key'],
                legacyKey: $dmarcItem['legacy_key'],
                priority: $priority,
                severity: $dmarcItem['severity'],
                title: $dmarcItem['title'],
                explanation: $dmarcItem['body'],
                action: match ($dmarcItem['semantic_key']) {
                    'add_dmarc' => 'Add DMARC record',
                    'fix_invalid_dmarc', 'fix_multiple_dmarc_records' => 'Fix DMARC',
                    'move_dmarc_from_none' => 'Upgrade to quarantine',
                    'add_dmarc_aggregate_reporting', 'add_mxscan_dmarc_reporting' => 'Add reporting',
                    'authorize_external_dmarc_reporting' => 'Verify authorization',
                    'increase_dmarc_percentage' => 'Increase coverage',
                    'review_dmarc_failure_reporting' => 'Check failure-report support',
                    'strengthen_dmarc_policy' => 'Verify alignment prerequisites',
                    default => 'Open DMARC solution',
                },
                recordName: '_dmarc.' . $domain->domain,
                value: $dmarcItem['suggested'],
                state: $dmarcItem['card_state'],
            );
        }

        $spfRecord = $records['SPF'] ?? null;
        $spfCard = $this->mapper->mapSpf($spfRecord, $spfInfo);

        foreach ($this->spfRecommendationEvaluator->evaluate($spfRecord, $spfCard, $spfInfo) as $spfItem) {
            $priority = match ($spfItem['legacy_key']) {
                'spf_missing', 'spf_invalid' => 4,
                default => 5,
            };
            $items[] = $this->item(
                semanticKey: $spfItem['semantic_key'],
                legacyKey: $spfItem['legacy_key'],
                priority: $priority,
                severity: $spfItem['severity'],
                title: $spfItem['title'],
                explanation: $spfItem['body'],
                action: in_array($spfItem['legacy_key'], ['spf_missing', 'spf_invalid'], true) ? 'Fix SPF' : 'Flatten SPF',
                recordName: $domain->domain,
                value: $spfItem['suggested'],
                state: $spfItem['card_state'],
            );
        }

        $dkim = $records['DKIM'] ?? null;
        $dkimInfo = $resultJson['dkim'] ?? null;
        $dkimCard = $this->mapper->mapDkim($dkim, $dkimInfo);

        foreach ($this->dkimRecommendationEvaluator->evaluate($dkimInfo, $dkimCard, null, $dkim) as $dkimItem) {
            $items[] = $this->item(
                semanticKey: $dkimItem['semantic_key'],
                legacyKey: $dkimItem['legacy_key'],
                priority: 6,
                severity: $dkimItem['severity'],
                title: $dkimItem['title'],
                explanation: $dkimItem['body'],
                action: match ($dkimItem['semantic_key']) {
                    'publish_dkim_key' => 'Configure DKIM DNS',
                    'provide_dkim_selector' => 'Provide selector',
                    'verify_dkim_signing_with_sample_message' => 'Verify signing',
                    default => 'Review DKIM',
                },
                recordName: null,
                value: $dkimItem['suggested'],
                state: $dkimItem['card_state'],
            );
        }

        $mxInfo = $resultJson['mx'] ?? null;
        $mxCard = $this->mapper->mapMx($records['MX'] ?? null, $mxInfo);

        foreach ($this->mxRecommendationEvaluator->evaluate($domain->domain, $mxInfo, $mxCard) as $mxItem) {
            $items[] = $this->item(
                semanticKey: $mxItem['semantic_key'],
                legacyKey: $mxItem['legacy_key'],
                priority: match ($mxItem['semantic_key']) {
                    'add_mx', 'fix_invalid_null_mx', 'fix_invalid_mx_record', 'fix_mx_hostname',
                    'replace_mx_cname', 'fix_dangling_mx', 'fix_non_public_mx_address' => 2,
                    'investigate_mx_dns_failure', 'review_implicit_mx_fallback' => 4,
                    default => 5,
                },
                severity: $mxItem['severity'],
                title: $mxItem['title'],
                explanation: $mxItem['body'],
                action: match ($mxItem['semantic_key']) {
                    'add_mx' => 'Add MX records',
                    'publish_null_mx' => 'Publish Null MX',
                    'fix_invalid_null_mx', 'fix_invalid_mx_record' => 'Fix MX records',
                    default => 'Review MX',
                },
                recordName: $domain->domain,
                value: $mxItem['suggested'],
                state: $mxItem['card_state'],
            );
        }

        $tlsRptInfo = $resultJson['tls_rpt'] ?? null;
        $tlsRptCard = $this->mapper->mapTlsRpt($records['TLS-RPT'] ?? null, $tlsRptInfo);

        foreach ($this->tlsRptRecommendationEvaluator->evaluate($domain->domain, $tlsRptInfo, $tlsRptCard) as $tlsRptItem) {
            $items[] = $this->item(
                semanticKey: $tlsRptItem['semantic_key'],
                legacyKey: $tlsRptItem['legacy_key'],
                priority: 7,
                severity: $tlsRptItem['severity'],
                title: $tlsRptItem['title'],
                explanation: $tlsRptItem['body'],
                action: match ($tlsRptItem['semantic_key']) {
                    'add_tls_rpt' => 'Add TLS-RPT',
                    'fix_invalid_tls_rpt_record', 'fix_multiple_tls_rpt_records' => 'Fix TLS-RPT',
                    'add_tls_rpt_destination', 'fix_tls_rpt_destination' => 'Fix destination',
                    default => 'Review TLS-RPT',
                },
                recordName: '_smtp._tls.' . $domain->domain,
                value: $tlsRptItem['suggested'],
                state: $tlsRptItem['card_state'],
            );
        }

        $mtaStsInfo = $resultJson['mta_sts'] ?? null;
        $mtaStsCard = $this->mapper->mapMtaSts($records['MTA-STS'] ?? null, $mtaStsInfo);

        foreach ($this->mtaStsRecommendationEvaluator->evaluate($domain->domain, $mtaStsInfo, $mtaStsCard) as $mtaStsItem) {
            $items[] = $this->item(
                semanticKey: $mtaStsItem['semantic_key'],
                legacyKey: $mtaStsItem['legacy_key'],
                priority: 8,
                severity: $mtaStsItem['severity'],
                title: $mtaStsItem['title'],
                explanation: $mtaStsItem['body'],
                action: match ($mtaStsItem['semantic_key']) {
                    'add_mta_sts' => 'Add MTA-STS',
                    'publish_mta_sts_policy' => 'Publish policy',
                    default => 'Open MTA-STS solution',
                },
                recordName: '_mta-sts.' . $domain->domain,
                value: $mtaStsItem['suggested'],
                state: $mtaStsItem['card_state'],
            );
        }

        $certificatesInfo = $resultJson['certificates'] ?? null;
        $certificatesCard = $this->mapper->mapCertificates($certificatesInfo);

        foreach ($this->certificateRecommendationEvaluator->evaluate($domain->domain, $certificatesInfo, $certificatesCard) as $certItem) {
            $items[] = $this->item(
                semanticKey: $certItem['semantic_key'],
                legacyKey: $certItem['legacy_key'],
                priority: match ($certItem['semantic_key']) {
                    'replace_expired_certificate', 'fix_certificate_hostname_mismatch',
                    'fix_untrusted_certificate_chain', 'fix_not_yet_valid_certificate' => 3,
                    'renew_expiring_certificate' => 5,
                    default => 6,
                },
                severity: $certItem['severity'],
                title: $certItem['title'],
                explanation: $certItem['body'],
                action: $certItem['title'],
                recordName: null,
                value: $certItem['suggested'] ?? null,
                state: $certItem['card_state'],
            );
        }

        $bimiInfo = $resultJson['bimi'] ?? null;
        $bimiCard = $this->mapper->mapBimi($records['BIMI'] ?? null, $bimiInfo);

        foreach ($this->bimiRecommendationEvaluator->evaluate($domain->domain, $bimiInfo, $bimiCard) as $bimiItem) {
            $items[] = $this->item(
                semanticKey: $bimiItem['semantic_key'],
                legacyKey: $bimiItem['legacy_key'],
                priority: match ($bimiItem['semantic_key']) {
                    'add_bimi_mark_certificate', 'review_bimi_provider_requirements' => 9,
                    default => 8,
                },
                severity: 'optional',
                title: $bimiItem['title'],
                explanation: $bimiItem['body'],
                action: $bimiItem['title'],
                recordName: 'default._bimi.' . $domain->domain,
                value: $bimiItem['suggested'] ?? null,
                state: $bimiItem['card_state'],
            );
        }

        $dmarcAnalysis = DmarcAnalysisReader::analysis(is_array($dmarcInfo) ? $dmarcInfo : null) ?? [];
        $alignmentVerified = ($dmarcAnalysis['alignment_verification'] ?? DmarcAlignmentVerification::NOT_VERIFIED)
            === DmarcAlignmentVerification::ALIGNED;
        $spfReady = in_array($spfCard['state'] ?? null, [ScanReportStatusMapper::PASS, ScanReportStatusMapper::WARNING], true);
        $dkimReady = in_array($dkimCard['state'] ?? null, [ScanReportStatusMapper::PASS, ScanReportStatusMapper::WARNING], true)
            && ($dkimCard['count'] ?? 0) > 0;

        foreach ($items as &$item) {
            if (($item['semantic_key'] ?? '') === 'strengthen_dmarc_policy' && !($spfReady && $dkimReady && $alignmentVerified)) {
                $item['title'] = 'DMARC reject policy';
                $item['explanation'] = 'Locked until SPF and DKIM alignment are verified.';
                $item['action'] = null;
                $item['locked'] = true;
                $item['actionable'] = false;
            }
        }
        unset($item);

        $items = (new RecommendationRanker())->sort($items);

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

        $mxInfo = $resultJson['mx'] ?? null;
        $mxAnalysis = MxAnalysisReader::analysis($mxInfo)
            ?? MxAnalysisReader::fromLegacyDnsRecord($records['MX'] ?? null, $mxInfo);
        $mxOk = in_array($mxAnalysis['risk_status'] ?? '', [MxRiskStatus::HEALTHY, MxRiskStatus::WARNING], true)
            && !in_array($mxAnalysis['state'] ?? '', [MxStates::FAIL, MxStates::MISSING], true);
        if (($mxAnalysis['service_mode'] ?? '') === MxServiceMode::UNKNOWN
            && ($mxAnalysis['risk_status'] ?? '') === MxRiskStatus::UNKNOWN) {
            $mxOk = false;
        }
        $spfCard = $this->mapper->mapSpf($records['SPF'] ?? null, $spfInfo);
        $dkimCard = $this->mapper->mapDkim($records['DKIM'] ?? null, $resultJson['dkim'] ?? null);
        $dmarcCard = $this->mapper->mapDmarc($records['DMARC'] ?? null, $resultJson['dmarc'] ?? null);
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

        $dkimOk = in_array($dkimCard['state'], [ScanReportStatusMapper::PASS, ScanReportStatusMapper::WARNING], true)
            && ($dkimCard['count'] ?? 0) >= 1;
        $dmarcOk = in_array($dmarcCard['state'], [ScanReportStatusMapper::PASS, ScanReportStatusMapper::WARNING], true)
            && ($dmarcCard['policy'] ?? null) !== 'none';

        $coreOk = $mxOk && $spfOk && $dkimOk && $dmarcOk;

        if (!$coreOk) {
            return [
                'state' => 'needs_fixes',
                'message' => null,
            ];
        }

        if (in_array($blacklistCard['state'], [ScanReportStatusMapper::NOT_CHECKED, ScanReportStatusMapper::UNKNOWN, ScanReportStatusMapper::WARNING], true)) {
            return [
                'state' => 'partial_clear',
                'message' => $blacklistCard['state'] === ScanReportStatusMapper::NOT_CHECKED
                    ? 'Core DNS authentication checks passed; blacklist status was not checked.'
                    : 'Core DNS authentication checks passed; blacklist reputation is incomplete or partial.',
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
        string $semanticKey,
        int $priority,
        string $severity,
        string $title,
        string $explanation,
        ?string $action,
        ?string $recordName,
        ?string $value,
        string $state,
        ?string $legacyKey = null,
    ): array {
        $legacyKey ??= $semanticKey;

        return [
            'semantic_key' => $semanticKey,
            'key' => $legacyKey,
            'source_rule' => $semanticKey,
            'priority' => $priority,
            'severity' => $severity,
            'title' => $title,
            'explanation' => $explanation,
            'action' => $action,
            'record_name' => $recordName,
            'value' => $value,
            'state' => $state,
            'actionable' => true,
            'locked' => false,
            'technical_target' => $this->technicalTarget($legacyKey),
        ];
    }

    protected function technicalTarget(string $key): ?string
    {
        return match (true) {
            str_starts_with($key, 'spf') => 'tech-spf',
            str_starts_with($key, 'dkim') => 'tech-dkim',
            str_starts_with($key, 'dmarc') => str_contains($key, 'rua') ? 'tech-dmarc_reports' : 'tech-dmarc',
            $key === 'mtasts' => 'tech-mtasts',
            $key === 'tlsrpt' => 'tech-tlsrpt',
            str_starts_with($key, 'blacklist') => 'tech-blacklist',
            default => null,
        };
    }
}
