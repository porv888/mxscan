<?php

namespace App\Domain\EmailSecurity\Reporting;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateStates;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistReputationStatus;
use App\Domain\EmailSecurity\Checks\Blacklist\Support\BlacklistAnalysisReader;
use App\Domain\EmailSecurity\Checks\DKIM\DkimStates;
use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimAnalysisReader;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcStates;
use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcAnalysisReader;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsStates;
use App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsAnalysisReader;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;
use App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader;
use App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptAnalysisReader;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptStates;
use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\BimiStates;
use App\Domain\EmailSecurity\Checks\SPF\Support\SpfAnalysisReader;

/**
 * Derives normalized display states from existing scan payloads.
 * Does not persist new enums into result_json / score_breakdown.
 */
class ScanReportStatusMapper
{
    public const PASS = 'pass';
    public const FAIL = 'fail';
    public const MISSING = 'missing';
    public const WARNING = 'warning';
    public const NOT_CHECKED = 'not_checked';
    public const NOT_APPLICABLE = 'not_applicable';
    public const UNKNOWN = 'unknown';

    /**
     * @param array<string, mixed> $resultJson
     * @param array<string, mixed> $records
     * @return array<string, mixed>
     */
    public function buildStatusCards(array $resultJson, array $records, ?int $score): array
    {
        return [
            'score' => [
                'label' => 'Email Security Score',
                'subtitle' => 'Authentication and transport-security configuration',
                'value' => $score,
            ],
            'blacklist' => $this->mapBlacklist($resultJson['blacklist'] ?? null),
            'spf' => $this->mapSpf($records['SPF'] ?? null, $resultJson['spf'] ?? null),
            'dkim' => $this->mapDkim($records['DKIM'] ?? null, $resultJson['dkim'] ?? null),
            'dmarc' => $this->mapDmarc($records['DMARC'] ?? null, $resultJson['dmarc'] ?? null),
            'mx' => $this->mapMx($records['MX'] ?? null, $resultJson['mx'] ?? null),
            'tlsrpt' => $this->mapTlsRpt($records['TLS-RPT'] ?? null, $resultJson['tls_rpt'] ?? null),
            'mtasts' => $this->mapMtaSts($records['MTA-STS'] ?? null, $resultJson['mta_sts'] ?? null),
            'bimi' => $this->mapBimi($records['BIMI'] ?? null, $resultJson['bimi'] ?? null),
        ];
    }

    /**
     * Map persisted score_breakdown status to display state.
     */
    public function mapBreakdownStatus(string $status): string
    {
        return match ($status) {
            'ok' => self::PASS,
            'missing' => self::MISSING,
            'partial' => self::WARNING,
            default => self::UNKNOWN,
        };
    }

    /**
     * @param array<string, mixed>|null $blacklist
     * @return array{state: string, label: string, subtext: string}
     */
    public function mapBlacklist(?array $blacklist): array
    {
        if ($blacklist === null) {
            return [
                'state' => self::NOT_CHECKED,
                'label' => 'Not scanned',
                'subtext' => 'Blacklist check did not run',
            ];
        }

        $analysis = BlacklistAnalysisReader::resolvedAnalysis($blacklist);
        $reputation = (string) ($analysis['reputation_status'] ?? BlacklistReputationStatus::NOT_CHECKED);
        $counts = is_array($analysis['counts'] ?? null) ? $analysis['counts'] : [];
        $usable = (int) ($counts['usable_results'] ?? 0);
        $listed = (int) ($counts['listed_results'] ?? ($blacklist['listed_count'] ?? 0));
        $planned = (int) ($counts['queries_planned'] ?? 0);

        return match ($reputation) {
            BlacklistReputationStatus::CLEAN => [
                'state' => self::PASS,
                'label' => 'Clean',
                'subtext' => $usable . ' lists checked',
            ],
            BlacklistReputationStatus::LISTED => [
                'state' => self::FAIL,
                'label' => 'Listed',
                'subtext' => $listed . ' detections across ' . $usable . ' checks',
            ],
            BlacklistReputationStatus::PARTIAL => [
                'state' => self::WARNING,
                'label' => 'Partial',
                'subtext' => 'No listings on completed checks; some providers unavailable',
            ],
            BlacklistReputationStatus::UNKNOWN => [
                'state' => self::UNKNOWN,
                'label' => 'Unknown',
                'subtext' => $planned > 0 ? '0 usable checks completed' : 'Blacklist could not be evaluated',
            ],
            default => [
                'state' => self::NOT_CHECKED,
                'label' => 'Not scanned',
                'subtext' => $usable === 0 ? '0 lists checked' : ($analysis['summary'] ?? 'Blacklist check did not run'),
            ],
        };
    }

    /**
     * @param array<string, mixed>|null $spfRecord
     * @param array<string, mixed>|null $spfInfo
     * @return array{card_label: string, state: string, status: string, subtext: string}
     */
    public function mapSpf(?array $spfRecord, ?array $spfInfo): array
    {
        $cardLabel = 'SPF';
        $recordStatus = $spfRecord['status'] ?? null;

        if ($recordStatus !== 'found') {
            return [
                'card_label' => $cardLabel,
                'state' => self::MISSING,
                'status' => 'Missing',
                'subtext' => 'Lookup count not applicable',
            ];
        }

        $uiState = SpfAnalysisReader::state($spfInfo);
        $protocolStatus = SpfAnalysisReader::protocolStatus($spfInfo);

        $valid = $spfInfo['valid'] ?? true;
        $error = $spfInfo['error'] ?? null;
        if ($valid === false) {
            return [
                'card_label' => $cardLabel,
                'state' => self::FAIL,
                'status' => 'Invalid',
                'subtext' => is_string($error) && $error !== ''
                    ? $error
                    : 'SPF configuration invalid',
            ];
        }

        if ($protocolStatus === 'temperror' || $uiState === self::UNKNOWN) {
            return [
                'card_label' => $cardLabel,
                'state' => self::UNKNOWN,
                'status' => 'Could not evaluate',
                'subtext' => SpfAnalysisReader::summary($spfInfo)
                    ?? 'SPF configuration could not be fully evaluated',
            ];
        }

        if ($spfInfo === null || !array_key_exists('lookups', $spfInfo) || $spfInfo['lookups'] === null) {
            return [
                'card_label' => $cardLabel,
                'state' => self::NOT_CHECKED,
                'status' => 'Not checked',
                'subtext' => 'Lookup calculation did not run',
            ];
        }

        $lookups = (int) $spfInfo['lookups'];
        if ($lookups > 10) {
            return [
                'card_label' => $cardLabel,
                'state' => self::FAIL,
                'status' => 'Over limit',
                'subtext' => $lookups . ' of 10 DNS lookups',
            ];
        }
        if ($lookups === 10) {
            return [
                'card_label' => $cardLabel,
                'state' => self::WARNING,
                'status' => 'At limit',
                'subtext' => $lookups . ' of 10 DNS lookups',
            ];
        }
        if ($lookups >= 7) {
            return [
                'card_label' => $cardLabel,
                'state' => self::WARNING,
                'status' => 'Near limit',
                'subtext' => $lookups . ' of 10 DNS lookups',
            ];
        }

        return [
            'card_label' => $cardLabel,
            'state' => self::PASS,
            'status' => 'OK',
            'subtext' => $lookups . ' of 10 DNS lookups',
        ];
    }

    /**
     * @param array<string, mixed>|null $dkim
     * @param array<string, mixed>|null $dkimInfo
     * @return array{state: string, status: string, explanation: string, count: int}
     */
    public function mapDkim(?array $dkim, ?array $dkimInfo = null): array
    {
        $explanation = 'This confirms published DNS keys only. Live signing and alignment require DMARC report or email-header evidence.';
        $analysis = DkimAnalysisReader::analysis($dkimInfo)
            ?? DkimAnalysisReader::fromLegacyDnsRecord($dkim, $dkimInfo);

        $state = $analysis['state'] ?? self::UNKNOWN;
        $summary = $analysis['summary'] ?? 'DKIM configuration could not be evaluated.';
        $selectors = is_array($analysis['selectors'] ?? null) ? $analysis['selectors'] : [];
        $validCount = count(array_filter(
            $selectors,
            fn (array $row) => ($row['record_status'] ?? '') === 'valid',
        ));

        $displayState = match ($state) {
            DkimStates::PASS => self::PASS,
            DkimStates::WARNING => self::WARNING,
            DkimStates::FAIL => self::FAIL,
            DkimStates::MISSING => self::MISSING,
            default => self::UNKNOWN,
        };

        return [
            'state' => $displayState,
            'status' => $summary,
            'explanation' => $explanation,
            'count' => $validCount > 0 ? $validCount : count($selectors),
        ];
    }

    /**
     * @param array<string, mixed>|null $dmarc dns.records.DMARC
     * @param array<string, mixed>|null $dmarcInfo result_json.dmarc
     * @return array{state: string, status: string, policy: string|null}
     */
    public function mapDmarc(?array $dmarc, ?array $dmarcInfo = null): array
    {
        $analysis = DmarcAnalysisReader::analysis($dmarcInfo)
            ?? DmarcAnalysisReader::fromLegacyDnsRecord($dmarc, $dmarcInfo);

        $state = $analysis['state'] ?? DmarcStates::UNKNOWN;
        $policy = is_array($analysis['policy'] ?? null)
            ? ($analysis['policy']['effective_policy'] ?? $analysis['policy']['published_p'] ?? null)
            : null;

        if ($state === DmarcStates::MISSING) {
            return [
                'state' => self::MISSING,
                'status' => 'Missing',
                'policy' => null,
            ];
        }

        if ($state === DmarcStates::FAIL) {
            return [
                'state' => self::FAIL,
                'status' => 'Invalid',
                'policy' => $policy,
            ];
        }

        if ($state === DmarcStates::UNKNOWN) {
            return [
                'state' => self::UNKNOWN,
                'status' => 'Unknown',
                'policy' => $policy,
            ];
        }

        if ($policy === 'none' || $state === DmarcStates::WARNING) {
            return [
                'state' => self::WARNING,
                'status' => $policy ? ('Policy ' . $policy) : 'Monitoring',
                'policy' => $policy,
            ];
        }

        return [
            'state' => self::PASS,
            'status' => $policy ? ('Policy ' . $policy) : 'Configured',
            'policy' => $policy,
        ];
    }

    /**
     * @param array<string, mixed>|null $record
     * @param array<string, mixed>|null $mxInfo
     * @return array{state: string, status: string}
     */
    public function mapMx(?array $record, ?array $mxInfo = null): array
    {
        $analysis = MxAnalysisReader::analysis($mxInfo)
            ?? MxAnalysisReader::fromLegacyDnsRecord($record, $mxInfo);

        $state = $analysis['state'] ?? MxStates::UNKNOWN;
        $summary = $analysis['summary'] ?? 'MX configuration could not be evaluated.';

        $displayState = match ($state) {
            MxStates::PASS => self::PASS,
            MxStates::WARNING => self::WARNING,
            MxStates::FAIL => self::FAIL,
            MxStates::MISSING => self::MISSING,
            default => self::UNKNOWN,
        };

        return [
            'state' => $displayState,
            'status' => $summary,
        ];
    }

    /**
     * @param array<string, mixed>|null $record
     * @param array<string, mixed>|null $mtaStsInfo
     * @return array{state: string, status: string}
     */
    public function mapMtaSts(?array $record, ?array $mtaStsInfo = null): array
    {
        $analysis = MtaStsAnalysisReader::analysis($mtaStsInfo)
            ?? MtaStsAnalysisReader::fromLegacyDnsRecord($record, $mtaStsInfo);

        $state = $analysis['state'] ?? MtaStsStates::UNKNOWN;
        $summary = $analysis['summary'] ?? 'MTA-STS configuration could not be evaluated.';
        $mode = is_array($analysis['policy'] ?? null) ? ($analysis['policy']['mode'] ?? null) : null;

        $displayState = match ($state) {
            MtaStsStates::PASS => self::PASS,
            MtaStsStates::WARNING => self::WARNING,
            MtaStsStates::FAIL => self::FAIL,
            MtaStsStates::MISSING => self::MISSING,
            default => self::UNKNOWN,
        };

        $status = match ($displayState) {
            self::PASS => 'Enforcement active',
            self::WARNING => $mode ? ('Mode ' . $mode) : $summary,
            self::FAIL => 'Invalid or broken',
            self::MISSING => 'Not set up',
            default => 'Unknown',
        };

        return [
            'state' => $displayState,
            'status' => $status,
        ];
    }

    /**
     * @param array<string, mixed>|null $certificatesInfo
     * @return array{state: string, status: string}
     */
    public function mapCertificates(?array $certificatesInfo): array
    {
        if ($certificatesInfo === null) {
            return [
                'state' => self::NOT_CHECKED,
                'status' => 'Not scanned',
            ];
        }

        $analysis = CertificateAnalysisReader::analysis($certificatesInfo);
        if ($analysis === null) {
            return [
                'state' => self::NOT_CHECKED,
                'status' => 'Not scanned',
            ];
        }

        $state = $analysis['state'] ?? CertificateStates::UNKNOWN;
        $summary = $analysis['summary'] ?? 'Certificate health could not be evaluated.';

        $displayState = match ($state) {
            CertificateStates::PASS => self::PASS,
            CertificateStates::WARNING => self::WARNING,
            CertificateStates::FAIL => self::FAIL,
            CertificateStates::NOT_CHECKED => self::NOT_CHECKED,
            default => self::UNKNOWN,
        };

        $status = match ($displayState) {
            self::PASS => 'All valid',
            self::WARNING => 'Expiring soon',
            self::FAIL => 'Action required',
            self::NOT_CHECKED => 'Not scanned',
            default => $summary,
        };

        return [
            'state' => $displayState,
            'status' => $status,
        ];
    }

    /**
     * @param array<string, mixed>|null $record
     * @param array<string, mixed>|null $tlsRptInfo
     * @return array{state: string, status: string}
     */
    public function mapTlsRpt(?array $record, ?array $tlsRptInfo = null): array
    {
        $analysis = TlsRptAnalysisReader::analysis($tlsRptInfo)
            ?? TlsRptAnalysisReader::fromLegacyDnsRecord($record, $tlsRptInfo);

        $state = $analysis['state'] ?? TlsRptStates::UNKNOWN;
        $summary = $analysis['summary'] ?? 'TLS-RPT configuration could not be evaluated.';

        $displayState = match ($state) {
            TlsRptStates::PASS => self::PASS,
            TlsRptStates::WARNING => self::WARNING,
            TlsRptStates::FAIL => self::FAIL,
            TlsRptStates::MISSING => self::MISSING,
            default => self::UNKNOWN,
        };

        $status = match ($displayState) {
            self::PASS => 'Configured',
            self::WARNING => $summary,
            self::FAIL => 'Invalid or broken',
            self::MISSING => 'Not set up',
            default => 'Unknown',
        };

        return [
            'state' => $displayState,
            'status' => $status,
        ];
    }

    /**
     * @param array<string, mixed>|null $record
     * @return array{state: string, status: string}
     */
    public function mapSimplePresence(?array $record, string $label): array
    {
        if (($record['status'] ?? '') === 'found') {
            return [
                'state' => self::PASS,
                'status' => 'Active',
            ];
        }

        return [
            'state' => self::MISSING,
            'status' => 'Not set up',
        ];
    }

    /**
     * @param array<string, mixed>|null $record
     * @param array<string, mixed>|null $bimiInfo
     * @return array{state: string, status: string, subtext: string}
     */
    public function mapBimi(?array $record, ?array $bimiInfo = null): array
    {
        $analysis = BimiAnalysisReader::analysis($bimiInfo)
            ?? BimiAnalysisReader::fromLegacyDnsRecord($record, $bimiInfo);

        $state = $analysis['state'] ?? BimiStates::UNKNOWN;
        $summary = $analysis['summary'] ?? 'BIMI configuration could not be evaluated.';

        $displayState = match ($state) {
            BimiStates::PASS => self::PASS,
            BimiStates::WARNING => self::WARNING,
            BimiStates::FAIL => self::FAIL,
            BimiStates::MISSING => self::MISSING,
            BimiStates::DECLINED => self::NOT_APPLICABLE,
            default => self::UNKNOWN,
        };

        $status = match ($displayState) {
            self::PASS => 'Ready',
            self::WARNING => $summary,
            self::FAIL => 'Needs attention',
            self::MISSING => 'Not set up',
            self::NOT_APPLICABLE => 'Not participating',
            default => 'Unknown',
        };

        return [
            'state' => $displayState,
            'status' => $status,
            'subtext' => 'Branding readiness — does not affect Email Security Score. Logo display remains subject to mailbox-provider policy.',
        ];
    }
}
