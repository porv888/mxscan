<?php

namespace App\Domain\EmailSecurity\Reporting;

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
            'dkim' => $this->mapDkim($records['DKIM'] ?? null),
            'dmarc' => $this->mapDmarc($records['DMARC'] ?? null),
            'tlsrpt' => $this->mapSimplePresence($records['TLS-RPT'] ?? null, 'TLS-RPT'),
            'mtasts' => $this->mapSimplePresence($records['MTA-STS'] ?? null, 'MTA-STS'),
            'bimi' => $this->mapBimi($records['BIMI'] ?? null),
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
        if ($blacklist === null || !array_key_exists('total_checks', $blacklist)) {
            return [
                'state' => self::NOT_CHECKED,
                'label' => 'Not scanned',
                'subtext' => 'Blacklist check did not run',
            ];
        }

        $total = (int) ($blacklist['total_checks'] ?? 0);
        $listed = (int) ($blacklist['listed_count'] ?? 0);

        if ($total === 0) {
            return [
                'state' => self::NOT_CHECKED,
                'label' => 'Not scanned',
                'subtext' => '0 lists checked',
            ];
        }

        if ($listed === 0) {
            return [
                'state' => self::PASS,
                'label' => 'Clean',
                'subtext' => $total . ' lists checked',
            ];
        }

        return [
            'state' => self::FAIL,
            'label' => 'Listed',
            'subtext' => $listed . ' detections across ' . $total . ' checks',
        ];
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

        $valid = $spfInfo['valid'] ?? true;
        $error = $spfInfo['error'] ?? null;
        if ($valid === false) {
            return [
                'card_label' => $cardLabel,
                'state' => self::FAIL,
                'status' => 'Invalid',
                'subtext' => is_string($error) && $error !== ''
                    ? $error
                    : 'SPF record failed validation',
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
        if ($lookups >= 10) {
            return [
                'card_label' => $cardLabel,
                'state' => self::FAIL,
                'status' => 'Over limit',
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
     * @return array{state: string, status: string, explanation: string, count: int}
     */
    public function mapDkim(?array $dkim): array
    {
        $explanation = 'This confirms published DNS keys only. Live signing and alignment require DMARC report or email-header evidence.';

        if (($dkim['status'] ?? '') === 'found' && !empty($dkim['data']) && is_array($dkim['data'])) {
            $count = count($dkim['data']);

            return [
                'state' => self::PASS,
                'status' => $count . ' DKIM selector' . ($count === 1 ? '' : 's') . ' discovered',
                'explanation' => $explanation,
                'count' => $count,
            ];
        }

        return [
            'state' => self::MISSING,
            'status' => 'No DKIM selectors discovered',
            'explanation' => $explanation,
            'count' => 0,
        ];
    }

    /**
     * @param array<string, mixed>|null $dmarc
     * @return array{state: string, status: string, policy: string|null}
     */
    public function mapDmarc(?array $dmarc): array
    {
        if (($dmarc['status'] ?? '') !== 'found') {
            return [
                'state' => self::MISSING,
                'status' => 'Missing',
                'policy' => null,
            ];
        }

        $txt = is_string($dmarc['data'] ?? null) ? $dmarc['data'] : '';
        $policy = null;
        if (preg_match('/p=([^;]+)/i', $txt, $m)) {
            $policy = trim($m[1]);
        }

        if ($policy === 'none') {
            return [
                'state' => self::WARNING,
                'status' => 'Policy none',
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
     * @param array<string, mixed>|null $bimi
     * @return array{state: string, status: string, subtext: string}
     */
    public function mapBimi(?array $bimi): array
    {
        if ($bimi === null) {
            return [
                'state' => self::NOT_APPLICABLE,
                'status' => 'Optional branding feature',
                'subtext' => 'Does not affect Email Security Score',
            ];
        }

        $status = $bimi['status'] ?? 'missing';
        if ($status === 'found') {
            return [
                'state' => self::PASS,
                'status' => 'Valid',
                'subtext' => 'Optional branding feature',
            ];
        }
        if ($status === 'partial') {
            return [
                'state' => self::WARNING,
                'status' => 'Partial',
                'subtext' => 'Optional branding feature',
            ];
        }

        return [
            'state' => self::NOT_APPLICABLE,
            'status' => 'Not set up',
            'subtext' => 'Optional branding feature — does not affect Email Security Score',
        ];
    }
}
