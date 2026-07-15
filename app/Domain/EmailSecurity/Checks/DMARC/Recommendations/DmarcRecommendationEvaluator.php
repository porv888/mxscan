<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Recommendations;

use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcProtocolStatus;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcStates;
use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcAnalysisReader;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Models\Domain;

/**
 * Native DMARC recommendation evaluation. Does not parse raw DMARC strings.
 */
final class DmarcRecommendationEvaluator
{
    /**
     * @param array<string, mixed>|null $dmarcInfo result_json.dmarc
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    public function evaluate(
        Domain $domain,
        ?array $dmarcCard,
        ?array $dmarcInfo = null,
        ?DmarcNativeResult $native = null,
    ): array {
        $analysis = DmarcAnalysisReader::analysis($dmarcInfo);
        $protocolStatus = $native?->protocolStatus ?? DmarcAnalysisReader::protocolStatus($dmarcInfo);
        $cardState = $dmarcCard['state'] ?? DmarcAnalysisReader::state($dmarcInfo) ?? ScanReportStatusMapper::UNKNOWN;

        if ($protocolStatus === DmarcProtocolStatus::NONE || $cardState === ScanReportStatusMapper::MISSING) {
            return [[
                'semantic_key' => 'add_dmarc',
                'legacy_key' => 'dmarc_missing',
                'severity' => 'high',
                'title' => 'Add DMARC Policy',
                'body' => 'Publish a DMARC TXT record so receivers know how to handle unauthenticated mail for your domain.',
                'suggested' => 'v=DMARC1; p=none; rua=mailto:' . $this->ruaAddress($domain) . ';',
                'card_state' => ScanReportStatusMapper::MISSING,
            ]];
        }

        if ($protocolStatus === DmarcProtocolStatus::PERMERROR) {
            $semantic = ($analysis['errors'][0]['code'] ?? '') === 'MULTIPLE_DMARC_RECORDS'
                ? 'fix_multiple_dmarc_records'
                : 'fix_invalid_dmarc';

            return [[
                'semantic_key' => $semantic,
                'legacy_key' => 'dmarc_invalid',
                'severity' => 'high',
                'title' => 'Fix Invalid DMARC Record',
                'body' => $analysis['summary'] ?? ($native?->summary ?? 'The published DMARC record is invalid.'),
                'suggested' => $analysis['record'] ?? $native?->rawRecord,
                'card_state' => ScanReportStatusMapper::FAIL,
            ]];
        }

        $items = [];
        $policy = is_array($analysis['policy'] ?? null) ? $analysis['policy'] : ($native?->policy ?? []);
        $aggregate = is_array($analysis['aggregate_reporting'] ?? null)
            ? $analysis['aggregate_reporting']
            : ($native?->aggregateReporting ?? []);

        $effectivePolicy = $policy['effective_policy'] ?? null;
        $pct = (int) ($policy['pct'] ?? 100);
        $enforcement = $policy['enforcement'] ?? null;

        if ($effectivePolicy === 'none' || $enforcement === 'monitoring') {
            $items[] = [
                'semantic_key' => 'move_dmarc_from_none',
                'legacy_key' => 'dmarc_policy',
                'severity' => 'high',
                'title' => 'Strengthen DMARC Policy',
                'body' => 'DMARC is in monitoring mode. After reviewing aggregate reports and alignment, move toward quarantine or reject.',
                'suggested' => 'v=DMARC1; p=quarantine; rua=mailto:' . $this->ruaAddress($domain) . ';',
                'card_state' => ScanReportStatusMapper::WARNING,
            ];
        }

        if ($pct < 100 && in_array($effectivePolicy, ['quarantine', 'reject'], true)) {
            $items[] = [
                'semantic_key' => 'increase_dmarc_percentage',
                'legacy_key' => 'dmarc_pct',
                'severity' => 'medium',
                'title' => 'Increase DMARC Percentage',
                'body' => 'DMARC enforcement applies to only part of failing mail. Increase coverage once senders are aligned.',
                'suggested' => null,
                'card_state' => ScanReportStatusMapper::WARNING,
            ];
        }

        if ($effectivePolicy === 'quarantine') {
            $items[] = [
                'semantic_key' => 'strengthen_dmarc_policy',
                'legacy_key' => 'dmarc_strengthen',
                'severity' => 'low',
                'title' => 'Consider Reject Policy',
                'body' => 'After sufficient monitoring, consider p=reject only when legitimate senders pass SPF/DKIM alignment.',
                'suggested' => null,
                'card_state' => ScanReportStatusMapper::WARNING,
            ];
        }

        if (!($aggregate['configured'] ?? false)) {
            $items[] = [
                'semantic_key' => 'add_dmarc_aggregate_reporting',
                'legacy_key' => 'dmarc_rua_missing',
                'severity' => 'medium',
                'title' => 'Add Aggregate Reporting',
                'body' => 'Configure a valid rua destination to receive DMARC aggregate reports.',
                'suggested' => 'rua=mailto:' . $this->ruaAddress($domain),
                'card_state' => ScanReportStatusMapper::WARNING,
            ];
        } else {
            foreach ($aggregate['destinations'] ?? [] as $destination) {
                if (($destination['authorization_status'] ?? '') === 'unauthorized') {
                    $items[] = [
                        'semantic_key' => 'authorize_external_dmarc_reporting',
                        'legacy_key' => 'dmarc_rua_unauthorized',
                        'severity' => 'medium',
                        'title' => 'Authorize External DMARC Reporting',
                        'body' => 'An external aggregate reporting destination is not authorized in DNS.',
                        'suggested' => null,
                        'card_state' => ScanReportStatusMapper::WARNING,
                    ];
                    break;
                }
            }
        }

        $mxscanExpectation = $aggregate['mxscan_expectation'] ?? [];
        if (($mxscanExpectation['expected_address'] ?? null) !== null
            && !($mxscanExpectation['present'] ?? false)) {
            $items[] = [
                'semantic_key' => 'add_mxscan_dmarc_reporting',
                'legacy_key' => 'dmarc_mxscan_rua',
                'severity' => 'medium',
                'title' => 'Add MXScan Reporting Address',
                'body' => 'Add the MXScan aggregate reporting address to your DMARC rua tag.',
                'suggested' => 'mailto:' . $mxscanExpectation['expected_address'],
                'card_state' => ScanReportStatusMapper::WARNING,
            ];
        }

        $failure = is_array($analysis['failure_reporting'] ?? null)
            ? $analysis['failure_reporting']
            : ($native?->failureReporting ?? []);
        if ($failure['configured'] ?? false) {
            $items[] = [
                'semantic_key' => 'review_dmarc_failure_reporting',
                'legacy_key' => 'dmarc_ruf',
                'severity' => 'low',
                'title' => 'Review Failure Reporting',
                'body' => 'Failure reporting (ruf) is configured. Receiver support varies; treat as optional visibility only.',
                'suggested' => null,
                'card_state' => ScanReportStatusMapper::WARNING,
            ];
        }

        $alignment = is_array($analysis['alignment'] ?? null) ? $analysis['alignment'] : ($native?->alignment ?? []);
        if (($alignment['dkim'] ?? 'relaxed') === 'strict' || ($alignment['spf'] ?? 'relaxed') === 'strict') {
            // strict alignment is already configured — no recommendation needed
        } elseif ($effectivePolicy === 'reject' && $enforcement === 'reject') {
            $items[] = [
                'semantic_key' => 'review_dmarc_alignment_hardening',
                'legacy_key' => 'dmarc_alignment_hardening',
                'severity' => 'low',
                'title' => 'Review Alignment Hardening',
                'body' => 'Strict DKIM/SPF alignment (adkim=s / aspf=s) is optional hardening after monitoring confirms alignment.',
                'suggested' => null,
                'card_state' => ScanReportStatusMapper::WARNING,
            ];
        }

        return $items;
    }

    private function ruaAddress(Domain $domain): string
    {
        if ($domain->exists && $domain->dmarc_rua_email) {
            return $domain->dmarc_rua_email;
        }

        return 'dmarc@' . $domain->domain;
    }
}
