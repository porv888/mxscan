<?php

namespace App\Domain\EmailSecurity\Support;

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

        $enabledCount = ($dns ? 1 : 0) + ($spf ? 1 : 0) + ($blacklist ? 1 : 0);

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
     */
    public static function blacklistStatusLabel(array $summary): string
    {
        if (($summary['total_checks'] ?? 0) <= 0) {
            return 'not-checked';
        }

        return !empty($summary['is_clean']) ? 'clean' : 'listed';
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

        if (isset($results['blacklist'])) {
            $facts['blacklist_status'] = self::blacklistStatusLabel($results['blacklist']);
            $facts['blacklist_count'] = $results['blacklist']['listed_count'] ?? 0;
        }

        return $facts;
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
