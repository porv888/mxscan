<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Recommendations;

use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxTargetResolver;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\MxProtocolStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;
use App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;

final class MxRecommendationEvaluator
{
    /**
     * @param array<string, mixed>|null $mxInfo
     * @param array<string, mixed>|null $mxCard
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    public function evaluate(
        string $domain,
        ?array $mxInfo,
        ?array $mxCard = null,
        ?MxNativeResult $native = null,
    ): array {
        $analysis = MxAnalysisReader::analysis($mxInfo);
        $protocolStatus = $native?->protocolStatus ?? MxAnalysisReader::protocolStatus($mxInfo);
        $serviceMode = $native?->serviceMode ?? MxAnalysisReader::serviceMode($mxInfo);
        $cardState = $mxCard['state'] ?? MxAnalysisReader::state($mxInfo) ?? ScanReportStatusMapper::UNKNOWN;
        $domain = strtolower(rtrim(trim($domain), '.'));
        $items = [];
        $seen = [];

        if (($native?->nullMx['valid'] ?? ($analysis['null_mx']['valid'] ?? false)) === true) {
            return [];
        }

        if ($protocolStatus === MxProtocolStatus::TEMPERROR) {
            return [$this->once($seen, $this->item(
                'investigate_mx_dns_failure',
                'Temporary DNS failure prevented reliable MX evaluation.',
                'medium',
                'Investigate MX DNS failure',
                ScanReportStatusMapper::UNKNOWN,
            ))];
        }

        if ($protocolStatus === MxProtocolStatus::NONE && $serviceMode !== MxServiceMode::IMPLICIT_DELIVERY) {
            return [$this->once($seen, $this->item(
                'add_mx',
                'Publish MX records so inbound email can be delivered to this domain.',
                'high',
                'Add MX records',
                ScanReportStatusMapper::MISSING,
            ))];
        }

        if (($native?->nullMx['mixed'] ?? ($analysis['null_mx']['published'] ?? false)) === true
            && ($native?->nullMx['valid'] ?? ($analysis['null_mx']['valid'] ?? false)) !== true) {
            return [$this->once($seen, $this->item(
                'fix_invalid_null_mx',
                'The Null MX configuration is invalid or mixed with ordinary MX records.',
                'high',
                'Fix Null MX configuration',
                ScanReportStatusMapper::FAIL,
            ))];
        }

        if ($serviceMode === MxServiceMode::IMPLICIT_DELIVERY) {
            $items[] = $this->once($seen, $this->item(
                'review_implicit_mx_fallback',
                'The domain relies on SMTP implicit-MX fallback instead of explicit MX records.',
                'medium',
                'Review implicit MX fallback',
                ScanReportStatusMapper::WARNING,
            ));
        }

        $targets = is_array($analysis['targets'] ?? null) ? $analysis['targets'] : ($native?->targets ?? []);
        foreach ($targets as $target) {
            $status = (string) ($target['status'] ?? '');
            $hostname = (string) ($target['normalized_hostname'] ?? $target['hostname'] ?? '');

            if ($status === MxTargetResolver::STATUS_ALIAS_INVALID) {
                $item = $this->once($seen, $this->item(
                    'replace_mx_cname',
                    "Replace the CNAME-based MX exchange {$hostname} with a direct hostname.",
                    'high',
                    'Replace MX CNAME target',
                    ScanReportStatusMapper::FAIL,
                ));
                if ($item !== null) {
                    $items[] = $item;
                }
            }

            if ($status === MxTargetResolver::STATUS_DANGLING) {
                $item = $this->once($seen, $this->item(
                    'fix_dangling_mx',
                    "Fix or remove the dangling MX target {$hostname}.",
                    'high',
                    'Fix dangling MX target',
                    ScanReportStatusMapper::FAIL,
                ));
                if ($item !== null) {
                    $items[] = $item;
                }
            }

            if ($status === MxTargetResolver::STATUS_NON_PUBLIC_ONLY) {
                $item = $this->once($seen, $this->item(
                    'fix_non_public_mx_address',
                    "MX target {$hostname} resolves only to non-public or invalid addresses.",
                    'high',
                    'Fix non-public MX address',
                    ScanReportStatusMapper::FAIL,
                ));
                if ($item !== null) {
                    $items[] = $item;
                }
            }

            if ($status === MxTargetResolver::STATUS_INVALID_HOSTNAME) {
                $item = $this->once($seen, $this->item(
                    'fix_mx_hostname',
                    "Fix the invalid MX hostname {$hostname}.",
                    'high',
                    'Fix MX hostname',
                    ScanReportStatusMapper::FAIL,
                ));
                if ($item !== null) {
                    $items[] = $item;
                }
            }

            if (in_array($status, [
                MxTargetResolver::STATUS_DANGLING,
                MxTargetResolver::STATUS_ALIAS_INVALID,
                MxTargetResolver::STATUS_NON_PUBLIC_ONLY,
                MxTargetResolver::STATUS_INVALID_HOSTNAME,
            ], true)) {
                $item = $this->once($seen, $this->item(
                    'remove_unusable_mx',
                    "Remove or replace unusable MX target {$hostname}.",
                    'medium',
                    'Remove unusable MX target',
                    ScanReportStatusMapper::WARNING,
                ));
                if ($item !== null) {
                    $items[] = $item;
                }
            }
        }

        foreach (($analysis['warnings'] ?? $native?->warnings ?? []) as $warning) {
            $code = (string) ($warning['code'] ?? '');
            if ($code === 'DUPLICATE_MX_RECORD') {
                $item = $this->once($seen, $this->item(
                    'remove_duplicate_mx_record',
                    'Remove duplicate identical MX records from the published RRset.',
                    'low',
                    'Remove duplicate MX record',
                    ScanReportStatusMapper::WARNING,
                ));
                if ($item !== null) {
                    $items[] = $item;
                }
            }
            if ($code === 'CONFLICTING_MX_PREFERENCES') {
                $item = $this->once($seen, $this->item(
                    'review_mx_preferences',
                    'Review MX hostnames published with conflicting preference values.',
                    'low',
                    'Review MX preferences',
                    ScanReportStatusMapper::WARNING,
                ));
                if ($item !== null) {
                    $items[] = $item;
                }
            }
        }

        if ($protocolStatus === MxProtocolStatus::PERMERROR) {
            $item = $this->once($seen, $this->item(
                'fix_invalid_mx_record',
                MxAnalysisReader::summary($mxInfo) ?? 'The published MX configuration needs attention.',
                'high',
                'Fix MX records',
                ScanReportStatusMapper::FAIL,
            ));
            if ($item !== null) {
                $items[] = $item;
            }
        }

        $usableTargets = (int) ($analysis['usable_targets'] ?? $native?->usableTargets ?? 0);
        if ($usableTargets === 1 && $cardState === MxStates::PASS) {
            $item = $this->once($seen, $this->item(
                'review_mx_redundancy',
                'A single MX host is valid, but additional MX hosts can improve resilience.',
                'low',
                'Review MX redundancy',
                ScanReportStatusMapper::PASS,
            ));
            if ($item !== null) {
                $items[] = $item;
            }
        }

        return array_values(array_filter($items));
    }

    /**
     * @param array<string, true> $seen
     * @return array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}|null
     */
    private function once(array &$seen, array $item): ?array
    {
        if (isset($seen[$item['semantic_key']])) {
            return null;
        }

        $seen[$item['semantic_key']] = true;

        return $item;
    }

    /**
     * @return array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}
     */
    private function item(
        string $semanticKey,
        string $body,
        string $severity,
        string $title,
        string $cardState,
    ): array {
        return [
            'semantic_key' => $semanticKey,
            'legacy_key' => 'mx',
            'severity' => $severity,
            'title' => $title,
            'body' => $body,
            'suggested' => null,
            'card_state' => $cardState,
        ];
    }
}
