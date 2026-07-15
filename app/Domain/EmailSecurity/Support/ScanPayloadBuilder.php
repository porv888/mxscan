<?php

namespace App\Domain\EmailSecurity\Support;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Domain\EmailSecurity\Checks\Blacklist\Support\BlacklistAnalysisReader;
use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimAnalysisReader;
use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcAnalysisReader;
use App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader;
use App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptAnalysisReader;
use App\Domain\EmailSecurity\Checks\SPF\Support\SpfAnalysisReader;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;

final class ScanPayloadBuilder
{
    /**
     * @param array<string, bool> $options
     */
    public static function determineScanType(array $options): string
    {
        $dns = $options['dns'] ?? true;
        $spf = $options['spf'] ?? true;
        $blacklist = $options['blacklist'] ?? true;
        $dkim = $options['dkim'] ?? false;

        $enabledCount = ($dns ? 1 : 0) + ($spf ? 1 : 0) + ($blacklist ? 1 : 0) + ($dkim ? 1 : 0);

        if ($enabledCount === 1) {
            if ($dns) {
                return 'dns';
            }
            if ($spf) {
                return 'spf';
            }
            if ($blacklist) {
                return 'blacklist';
            }
            if ($dkim) {
                return 'dkim';
            }
        }

        return 'full';
    }

    /**
     * @return array<string, mixed>
     */
    public static function buildSpfResultPayload(SpfResultDTO $spfResult): array
    {
        $warnings = $spfResult->warnings;
        $invalid = in_array(SpfResolver::WARNING_PLUS_ALL, $warnings, true)
            || in_array(SpfResolver::WARNING_MULTIPLE_SPF, $warnings, true);
        $error = null;
        if (in_array(SpfResolver::WARNING_PLUS_ALL, $warnings, true)) {
            $error = 'SPF uses +all which allows any sender.';
        } elseif (in_array(SpfResolver::WARNING_MULTIPLE_SPF, $warnings, true)) {
            $error = 'Multiple SPF records found; only one is allowed.';
        }

        $lookups = $spfResult->lookupsUsed;
        $status = $lookups >= 10 ? 'error' : ($lookups >= 9 ? 'warning' : 'safe');
        if ($invalid) {
            $status = 'error';
        }

        return [
            'record' => $spfResult->currentRecord,
            'lookups' => $lookups,
            'flattened' => $spfResult->flattenedSpf,
            'status' => $status,
            'valid' => !$invalid && $spfResult->currentRecord !== null,
            'error' => $error,
            'warnings' => $warnings,
        ];
    }

    /**
     * @param array<string, mixed> $summary
     * @deprecated Use BlacklistAnalysisReader::facts()
     */
    public static function blacklistStatusLabel(array $summary): string
    {
        return BlacklistAnalysisReader::compatStatusLabel(
            (string) (BlacklistAnalysisReader::resolvedAnalysis($summary)['reputation_status'] ?? 'not_checked'),
        );
    }

    /**
     * Facts payload used by async RunFullScan persistence.
     *
     * @param array<string, mixed> $results
     * @return array<string, mixed>
     */
    public static function buildFactsForAsyncJob(array $results): array
    {
        $facts = [
            'spf_record' => $results['spf']['record'] ?? null,
            'spf_lookups' => $results['spf']['lookups'] ?? null,
            'blacklist_status' => isset($results['blacklist'])
                ? self::blacklistStatusLabel($results['blacklist'])
                : null,
            'blacklist_count' => $results['blacklist']['listed_count'] ?? null,
        ];

        if (isset($results['blacklist']) && is_array($results['blacklist'])) {
            $facts = array_merge($facts, BlacklistAnalysisReader::facts($results['blacklist']));
        }

        if (isset($results['spf']) && is_array($results['spf'])) {
            $protocolStatus = SpfAnalysisReader::protocolStatus($results['spf']);
            $riskStatus = SpfAnalysisReader::riskStatus($results['spf']);
            $terminalPolicy = SpfAnalysisReader::terminalPolicy($results['spf']);

            if ($protocolStatus !== null) {
                $facts['spf_protocol_status'] = $protocolStatus;
            }
            if ($riskStatus !== null) {
                $facts['spf_risk_status'] = $riskStatus;
            }
            if ($terminalPolicy !== null) {
                $facts['spf_terminal_policy'] = $terminalPolicy;
            }
        }

        if (isset($results['dmarc']) && is_array($results['dmarc'])) {
            $facts = array_merge($facts, self::dmarcFacts($results['dmarc']));
        }

        if (isset($results['dkim']) && is_array($results['dkim'])) {
            $facts = array_merge($facts, self::dkimFacts($results['dkim']));
        }

        if (isset($results['tls_rpt']) && is_array($results['tls_rpt'])) {
            $facts = array_merge($facts, self::tlsRptFacts($results['tls_rpt']));
        }

        if (isset($results['mx']) && is_array($results['mx'])) {
            $facts = array_merge($facts, self::mxFacts($results['mx']));
        }

        if (isset($results['certificates']) && is_array($results['certificates'])) {
            $facts = array_merge($facts, CertificateAnalysisReader::facts($results['certificates']));
        }

        if (isset($results['bimi']) && is_array($results['bimi'])) {
            $facts = array_merge($facts, BimiAnalysisReader::facts($results['bimi']));
        }

        return $facts;
    }

    /**
     * @param array<string, mixed>|null $dmarc
     * @return array<string, mixed>
     */
    private static function dmarcFacts(?array $dmarc): array
    {
        if ($dmarc === null) {
            return [];
        }

        $facts = [];
        $analysis = DmarcAnalysisReader::analysis($dmarc);
        $record = is_array($analysis) ? ($analysis['record'] ?? null) : null;
        if (!is_string($record) || $record === '') {
            $record = is_string($dmarc['record'] ?? null) ? $dmarc['record'] : null;
        }
        if ($record !== null && $record !== '') {
            $facts['dmarc'] = $record;
            $facts['dmarc_record'] = $record;
        }

        $protocolStatus = DmarcAnalysisReader::protocolStatus($dmarc);
        if ($protocolStatus !== null) {
            $facts['dmarc_protocol_status'] = $protocolStatus;
        }

        $riskStatus = DmarcAnalysisReader::riskStatus($dmarc);
        if ($riskStatus !== null) {
            $facts['dmarc_risk_status'] = $riskStatus;
        }

        $effectivePolicy = DmarcAnalysisReader::effectivePolicy($dmarc);
        if ($effectivePolicy !== null) {
            $facts['dmarc_effective_policy'] = $effectivePolicy;
        }

        return $facts;
    }

    /**
     * @param array<string, mixed>|null $dkim
     * @return array<string, mixed>
     */
    private static function dkimFacts(?array $dkim): array
    {
        if ($dkim === null) {
            return [];
        }

        $facts = [];
        $protocolStatus = DkimAnalysisReader::protocolStatus($dkim);
        if ($protocolStatus !== null) {
            $facts['dkim_protocol_status'] = $protocolStatus;
        }

        return $facts;
    }

    /**
     * Facts payload used by synchronous ScanRunner persistence.
     *
     * @param array<string, mixed> $results
     * @return array<string, mixed>
     */
    public static function buildFactsForSyncRunner(array $results, ?SpfResultDTO $spfResult = null): array
    {
        $facts = [];

        if ($spfResult !== null) {
            $facts['spf_record'] = $spfResult->currentRecord ?: 'No SPF record found';
            $facts['spf_lookups'] = $spfResult->lookupsUsed;
        }

        if (isset($results['spf']) && is_array($results['spf'])) {
            $protocolStatus = SpfAnalysisReader::protocolStatus($results['spf']);
            $riskStatus = SpfAnalysisReader::riskStatus($results['spf']);
            $terminalPolicy = SpfAnalysisReader::terminalPolicy($results['spf']);

            if ($protocolStatus !== null) {
                $facts['spf_protocol_status'] = $protocolStatus;
            }
            if ($riskStatus !== null) {
                $facts['spf_risk_status'] = $riskStatus;
            }
            if ($terminalPolicy !== null) {
                $facts['spf_terminal_policy'] = $terminalPolicy;
            }
        }

        if (isset($results['blacklist']) && is_array($results['blacklist'])) {
            $facts = array_merge($facts, BlacklistAnalysisReader::facts($results['blacklist']));
        }

        if (isset($results['dmarc']) && is_array($results['dmarc'])) {
            $facts = array_merge($facts, self::dmarcFacts($results['dmarc']));
        }

        if (isset($results['dkim']) && is_array($results['dkim'])) {
            $facts = array_merge($facts, self::dkimFacts($results['dkim']));
        }

        if (isset($results['tls_rpt']) && is_array($results['tls_rpt'])) {
            $facts = array_merge($facts, self::tlsRptFacts($results['tls_rpt']));
        }

        if (isset($results['mx']) && is_array($results['mx'])) {
            $facts = array_merge($facts, self::mxFacts($results['mx']));
        }

        if (isset($results['certificates']) && is_array($results['certificates'])) {
            $facts = array_merge($facts, CertificateAnalysisReader::facts($results['certificates']));
        }

        if (isset($results['bimi']) && is_array($results['bimi'])) {
            $facts = array_merge($facts, BimiAnalysisReader::facts($results['bimi']));
        }

        return $facts;
    }

    /**
     * @param array<string, mixed>|null $mx
     * @return array<string, mixed>
     */
    private static function mxFacts(?array $mx): array
    {
        if ($mx === null) {
            return [];
        }

        $analysis = MxAnalysisReader::analysis($mx);
        if ($analysis === null) {
            return [];
        }

        $facts = [];
        foreach ([
            'protocol_status' => 'mx_protocol_status',
            'risk_status' => 'mx_risk_status',
            'service_mode' => 'mx_service_mode',
        ] as $source => $target) {
            if (is_string($analysis[$source] ?? null)) {
                $facts[$target] = $analysis[$source];
            }
        }

        foreach ([
            'records_total' => 'mx_record_count',
            'usable_targets' => 'mx_usable_target_count',
            'invalid_targets' => 'mx_invalid_target_count',
        ] as $source => $target) {
            if (isset($analysis[$source])) {
                $facts[$target] = (int) $analysis[$source];
            }
        }

        $nullMx = is_array($analysis['null_mx'] ?? null) ? $analysis['null_mx'] : [];
        if (array_key_exists('published', $nullMx)) {
            $facts['mx_null_published'] = (bool) $nullMx['published'];
        }
        if (array_key_exists('valid', $nullMx)) {
            $facts['mx_null_valid'] = (bool) $nullMx['valid'];
        }

        $implicit = is_array($analysis['implicit_fallback'] ?? null) ? $analysis['implicit_fallback'] : [];
        if (array_key_exists('active', $implicit)) {
            $facts['mx_implicit_fallback'] = (bool) $implicit['active'];
        }

        $targets = is_array($analysis['targets'] ?? null) ? $analysis['targets'] : [];
        $facts['mx_has_ipv4'] = self::mxHasAddressFamily($targets, 'a_addresses');
        $facts['mx_has_ipv6'] = self::mxHasAddressFamily($targets, 'aaaa_addresses');
        $facts['mx_has_cname_target'] = self::mxHasTargetFlag($targets, 'is_alias', true);
        $facts['mx_has_dangling_target'] = self::mxHasTargetStatus($targets, 'dangling');

        return $facts;
    }

    /**
     * @param list<array<string, mixed>> $targets
     */
    private static function mxHasAddressFamily(array $targets, string $key): bool
    {
        foreach ($targets as $target) {
            $addresses = is_array($target[$key] ?? null) ? $target[$key] : [];
            foreach ($addresses as $address) {
                if (($address['usable'] ?? false) === true) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param list<array<string, mixed>> $targets
     */
    private static function mxHasTargetFlag(array $targets, string $key, bool $expected): bool
    {
        foreach ($targets as $target) {
            if (($target[$key] ?? null) === $expected) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<array<string, mixed>> $targets
     */
    private static function mxHasTargetStatus(array $targets, string $status): bool
    {
        foreach ($targets as $target) {
            if (($target['status'] ?? '') === $status) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed>|null $tlsRpt
     * @return array<string, mixed>
     */
    private static function tlsRptFacts(?array $tlsRpt): array
    {
        if ($tlsRpt === null) {
            return [];
        }

        $facts = [];
        $analysis = TlsRptAnalysisReader::analysis($tlsRpt);

        $protocolStatus = TlsRptAnalysisReader::protocolStatus($tlsRpt);
        if ($protocolStatus !== null) {
            $facts['tls_rpt_protocol_status'] = $protocolStatus;
        }

        $riskStatus = TlsRptAnalysisReader::riskStatus($tlsRpt);
        if ($riskStatus !== null) {
            $facts['tls_rpt_risk_status'] = $riskStatus;
        }

        $state = TlsRptAnalysisReader::state($tlsRpt);
        if ($state !== null) {
            $facts['tls_rpt_configured'] = $state === 'pass';
        }

        $reporting = is_array($analysis['reporting'] ?? null) ? $analysis['reporting'] : [];
        if ($reporting !== []) {
            if (isset($reporting['destinations_total'])) {
                $facts['tls_rpt_destination_count'] = (int) $reporting['destinations_total'];
            }
            if (isset($reporting['valid_destinations'])) {
                $facts['tls_rpt_valid_destination_count'] = (int) $reporting['valid_destinations'];
            }

            $destinations = is_array($reporting['destinations'] ?? null) ? $reporting['destinations'] : [];
            $facts['tls_rpt_has_mailto'] = self::tlsRptHasScheme($destinations, 'mailto');
            $facts['tls_rpt_has_https'] = self::tlsRptHasScheme($destinations, 'https');

            $expected = is_array($reporting['expected_destination'] ?? null) ? $reporting['expected_destination'] : [];
            if (array_key_exists('present', $expected)) {
                $facts['tls_rpt_expected_destination_present'] = (bool) $expected['present'];
            }
        }

        return $facts;
    }

    /**
     * @param list<array<string, mixed>> $destinations
     */
    private static function tlsRptHasScheme(array $destinations, string $scheme): bool
    {
        foreach ($destinations as $destination) {
            if (($destination['status'] ?? '') === 'valid' && ($destination['scheme'] ?? '') === $scheme) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $results
     * @return array<string, mixed>
     */
    public static function buildBroadcastReport(array $results): array
    {
        $report = [
            'timestamp' => now()->toISOString(),
            'summary' => [],
        ];

        if (isset($results['dns'])) {
            $report['summary']['dns_score'] = $results['dns']['score'];
            $report['dns'] = $results['dns'];
        }

        if (isset($results['spf'])) {
            $report['summary']['spf_status'] = $results['spf']['status'];
            $report['summary']['spf_lookups'] = $results['spf']['lookups'];
            $report['spf'] = $results['spf'];
        }

        if (isset($results['blacklist'])) {
            $report['summary']['blacklist_status'] = self::blacklistStatusLabel($results['blacklist']);
            $report['summary']['blacklist_count'] = $results['blacklist']['listed_count'] ?? 0;
            $report['blacklist'] = $results['blacklist'];
        }

        return $report;
    }

    /**
     * @param array<string, mixed> $artifacts
     */
    public static function legacySpfRawFromArtifacts(array $artifacts): ?SpfResultDTO
    {
        $raw = $artifacts[ScanArtifactKeys::LEGACY_SPF_RAW] ?? null;

        return $raw instanceof SpfResultDTO ? $raw : null;
    }
}
