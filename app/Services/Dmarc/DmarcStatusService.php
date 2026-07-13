<?php

namespace App\Services\Dmarc;

use App\Models\Domain;
use Illuminate\Support\Facades\Log;

/**
 * Unified DMARC Setup Status Evaluator
 *
 * This service provides a single source of truth for DMARC setup status
 * across all pages: Scan page, DMARC Activity (global), and Domain DMARC Visibility page.
 *
 * Lifecycle status (not_enabled … stale) is orthogonal to rua_link_state
 * (connected | detected_unlinked | not_connected).
 */
class DmarcStatusService
{
    // Status constants - these are the 5 defined lifecycle states
    public const STATUS_NOT_ENABLED = 'not_enabled';
    public const STATUS_ENABLED_NOT_MXSCAN = 'enabled_not_mxscan';
    public const STATUS_ENABLED_MXSCAN_WAITING = 'enabled_mxscan_waiting';
    public const STATUS_ACTIVE = 'active';
    public const STATUS_STALE = 'stale';

    public const RUA_LINK_CONNECTED = 'connected';
    public const RUA_LINK_DETECTED_UNLINKED = 'detected_unlinked';
    public const RUA_LINK_NOT_CONNECTED = 'not_connected';

    // Default threshold for stale reports (days)
    public const DEFAULT_STALE_THRESHOLD_DAYS = 7;

    public function __construct(
        protected DmarcRuaClassifier $ruaClassifier = new DmarcRuaClassifier(),
        protected DmarcDnsLookup $dnsLookup = new DmarcDnsLookup()
    ) {
    }

    /**
     * Get the unified DMARC setup status for a domain.
     *
     * @param Domain $domain
     * @param int $staleThresholdDays Days after which reports are considered stale
     * @return array{
     *   status: string,
     *   label: string,
     *   badge_color: string,
     *   helper_text: string,
     *   cta_text: string|null,
     *   cta_action: string|null,
     *   has_dmarc_record: bool,
     *   has_rua: bool,
     *   has_mxscan_rua: bool,
     *   has_reports: bool,
     *   last_report_at: \Carbon\Carbon|null,
     *   last_dns_check_at: \Carbon\Carbon|null,
     *   checklist: array,
     *   rua_link_state: string,
     *   rua_link_label: string,
     *   rua_link_cta: string|null,
     *   has_any_mxscan_rua: bool,
     *   has_canonical_mxscan_rua: bool
     * }
     */
    public function getStatus(Domain $domain, int $staleThresholdDays = self::DEFAULT_STALE_THRESHOLD_DAYS): array
    {
        $hasDmarcRecord = $this->hasDmarcRecord($domain);
        $hasRua = $this->hasRuaInDmarc($domain);
        $link = $this->classifyDomainRua($domain);
        $hasCanonicalMxscanRua = $link['has_canonical_mxscan_rua'];
        $hasAnyMxscanRua = $link['has_any_mxscan_rua'];
        $ruaLinkState = $link['rua_link_state'];

        // Existing has_mxscan_rua means canonical link (drives lifecycle).
        $hasMxscanRua = $hasCanonicalMxscanRua;

        $hasReports = $domain->dmarc_last_report_at !== null;
        $lastReportAt = $domain->dmarc_last_report_at;
        $lastDnsCheckAt = $domain->dmarc_rua_verified_at ?? $domain->last_scanned_at;

        $isStale = false;
        if ($hasReports && $lastReportAt) {
            $isStale = $lastReportAt->lt(now()->subDays($staleThresholdDays));
        }

        $status = $this->determineStatus(
            $hasDmarcRecord,
            $hasRua,
            $hasMxscanRua,
            $hasReports,
            $isStale
        );

        $ctaAction = $this->getCtaAction($status);
        $ctaText = $this->getCtaText($status);

        // When DMARC+RUA exist, connection CTAs come from rua_link_state.
        if ($hasDmarcRecord && $hasRua) {
            if ($ruaLinkState === self::RUA_LINK_DETECTED_UNLINKED) {
                $ctaAction = 'relink';
                $ctaText = 'Relink MXScan reporting';
            } elseif ($ruaLinkState === self::RUA_LINK_NOT_CONNECTED) {
                $ctaAction = 'add_rua';
                $ctaText = 'Connect MXScan reporting';
            }
        }

        return [
            'status' => $status,
            'label' => $this->getStatusLabel($status),
            'badge_color' => $this->getBadgeColor($status),
            'helper_text' => $this->getHelperText($status, $lastReportAt),
            'cta_text' => $ctaText,
            'cta_action' => $ctaAction,
            'has_dmarc_record' => $hasDmarcRecord,
            'has_rua' => $hasRua,
            'has_mxscan_rua' => $hasMxscanRua,
            'has_reports' => $hasReports,
            'is_stale' => $isStale,
            'last_report_at' => $lastReportAt,
            'last_dns_check_at' => $lastDnsCheckAt,
            'checklist' => $this->buildChecklist($hasDmarcRecord, $hasMxscanRua, $hasReports),
            'rua_link_state' => $ruaLinkState,
            'rua_link_label' => $this->getRuaLinkLabel($ruaLinkState),
            'rua_link_cta' => $this->getRuaLinkCta($ruaLinkState),
            'has_any_mxscan_rua' => $hasAnyMxscanRua,
            'has_canonical_mxscan_rua' => $hasCanonicalMxscanRua,
        ];
    }

    /**
     * Determine the lifecycle status based on inputs.
     */
    protected function determineStatus(
        bool $hasDmarcRecord,
        bool $hasRua,
        bool $hasMxscanRua,
        bool $hasReports,
        bool $isStale
    ): string {
        if (!$hasDmarcRecord || !$hasRua) {
            return self::STATUS_NOT_ENABLED;
        }

        if (!$hasMxscanRua) {
            return self::STATUS_ENABLED_NOT_MXSCAN;
        }

        if ($hasReports && $isStale) {
            return self::STATUS_STALE;
        }

        if ($hasReports) {
            return self::STATUS_ACTIVE;
        }

        return self::STATUS_ENABLED_MXSCAN_WAITING;
    }

    /**
     * Check if domain has a DMARC record in DNS (from latest scan).
     */
    protected function hasDmarcRecord(Domain $domain): bool
    {
        $dmarcRecord = $this->getDmarcRecord($domain);
        return !empty($dmarcRecord);
    }

    /**
     * Check if DMARC record has any RUA address.
     */
    protected function hasRuaInDmarc(Domain $domain): bool
    {
        $dmarcRecord = $this->getDmarcRecord($domain);
        if (!$dmarcRecord) {
            return false;
        }

        $parts = $this->ruaClassifier->parseDmarcTags($dmarcRecord);
        if (!isset($parts['rua']) || trim($parts['rua']) === '') {
            return false;
        }

        return count($this->ruaClassifier->parseRuaRecipients($parts['rua'])) > 0;
    }

    /**
     * Check if DMARC record includes the canonical MXScan RUA address.
     * Does not trust dmarc_rua_verified_at alone.
     */
    protected function hasMxscanRua(Domain $domain): bool
    {
        return $this->classifyDomainRua($domain)['has_canonical_mxscan_rua'];
    }

    /**
     * Classify the domain's current scan/DNS DMARC RUA link state.
     *
     * @return array{
     *   rua_link_state: string,
     *   has_any_mxscan_rua: bool,
     *   has_canonical_mxscan_rua: bool,
     *   recipients: list,
     *   mxscan_recipients: list,
     *   external_recipients: list
     * }
     */
    protected function classifyDomainRua(Domain $domain): array
    {
        $dmarcRecord = $this->getDmarcRecord($domain);
        if (!$dmarcRecord) {
            return [
                'rua_link_state' => self::RUA_LINK_NOT_CONNECTED,
                'has_any_mxscan_rua' => false,
                'has_canonical_mxscan_rua' => false,
                'recipients' => [],
                'mxscan_recipients' => [],
                'external_recipients' => [],
            ];
        }

        return $this->ruaClassifier->classify($dmarcRecord, $domain->dmarc_rua_email);
    }

    /**
     * Get the DMARC record used for status classification.
     *
     * Prefers the last verified live DNS snapshot after an explicit Check DNS.
     * Falls back to the latest finished/completed scan.
     */
    protected function getDmarcRecord(Domain $domain): ?string
    {
        if ($domain->dmarc_dns_record && $domain->dmarc_rua_verified_at) {
            return $domain->dmarc_dns_record;
        }

        $latestScan = $this->latestCompletedScan($domain);

        if (!$latestScan) {
            return null;
        }

        $factsJson = $latestScan->facts_json;
        if (is_array($factsJson) && isset($factsJson['dmarc']) && !empty($factsJson['dmarc'])) {
            return $factsJson['dmarc'];
        }

        $resultJson = $latestScan->result_json;
        if (is_array($resultJson)) {
            $dmarcData = $resultJson['dns']['records']['DMARC'] ?? $resultJson['DMARC'] ?? null;
            if ($dmarcData && isset($dmarcData['data']) && ($dmarcData['status'] ?? null) === 'found') {
                return $dmarcData['data'];
            }
        }

        return null;
    }

    /**
     * Latest scan with a completed status (canonical: finished; legacy: completed).
     */
    protected function latestCompletedScan(Domain $domain)
    {
        return $domain->scans()
            ->whereIn('status', ['finished', 'completed'])
            ->latest()
            ->first();
    }

    /**
     * Get human-readable lifecycle status label.
     */
    public function getStatusLabel(string $status): string
    {
        return match ($status) {
            self::STATUS_NOT_ENABLED => 'Not Enabled',
            self::STATUS_ENABLED_NOT_MXSCAN => 'Enabled (Not to MXScan)',
            self::STATUS_ENABLED_MXSCAN_WAITING => 'Enabled (MXScan) — Waiting',
            self::STATUS_ACTIVE => 'Active',
            self::STATUS_STALE => 'Stale',
            default => 'Unknown',
        };
    }

    public function getRuaLinkLabel(string $ruaLinkState): string
    {
        return match ($ruaLinkState) {
            self::RUA_LINK_CONNECTED => 'MXScan reporting connected',
            self::RUA_LINK_DETECTED_UNLINKED => 'MXScan reporting is present, but it is not linked to this domain.',
            self::RUA_LINK_NOT_CONNECTED => 'DMARC is active. Connect MXScan reporting to identify senders and authentication failures.',
            default => 'DMARC active — MXScan reporting not connected',
        };
    }

    public function getRuaLinkCta(string $ruaLinkState): ?string
    {
        return match ($ruaLinkState) {
            self::RUA_LINK_CONNECTED => null,
            self::RUA_LINK_DETECTED_UNLINKED => 'Relink MXScan reporting',
            self::RUA_LINK_NOT_CONNECTED => 'Connect MXScan reporting',
            default => null,
        };
    }

    /**
     * Get badge color for UI display.
     */
    public function getBadgeColor(string $status): string
    {
        return match ($status) {
            self::STATUS_NOT_ENABLED => 'gray',
            self::STATUS_ENABLED_NOT_MXSCAN => 'amber',
            self::STATUS_ENABLED_MXSCAN_WAITING => 'blue',
            self::STATUS_ACTIVE => 'green',
            self::STATUS_STALE => 'amber',
            default => 'gray',
        };
    }

    /**
     * Get helper text based on status.
     */
    public function getHelperText(string $status, ?\Carbon\Carbon $lastReportAt = null): string
    {
        return match ($status) {
            self::STATUS_NOT_ENABLED => 'Add an RUA address to start receiving aggregate reports.',
            self::STATUS_ENABLED_NOT_MXSCAN => "You're sending reports elsewhere. Add MXScan to see sender visibility here.",
            self::STATUS_ENABLED_MXSCAN_WAITING => 'Good — reports usually arrive within 24–48 hours.',
            self::STATUS_ACTIVE => $lastReportAt
                ? 'Last report: ' . $lastReportAt->diffForHumans()
                : 'Receiving reports.',
            self::STATUS_STALE => $lastReportAt
                ? 'Last report: ' . $lastReportAt->diffForHumans() . '. Check DNS / provider sending / forwarding issues.'
                : 'No recent reports. Check DNS / provider sending / forwarding issues.',
            default => '',
        };
    }

    /**
     * Get CTA button text.
     */
    public function getCtaText(string $status): ?string
    {
        return match ($status) {
            self::STATUS_NOT_ENABLED => 'Enable DMARC Reporting',
            self::STATUS_ENABLED_NOT_MXSCAN => 'Add MXScan RUA',
            self::STATUS_ENABLED_MXSCAN_WAITING => 'View DMARC Activity',
            self::STATUS_ACTIVE => 'View DMARC Activity',
            self::STATUS_STALE => 'Check DNS',
            default => null,
        };
    }

    /**
     * Get CTA action type.
     */
    public function getCtaAction(string $status): ?string
    {
        return match ($status) {
            self::STATUS_NOT_ENABLED => 'setup',
            self::STATUS_ENABLED_NOT_MXSCAN => 'add_rua',
            self::STATUS_ENABLED_MXSCAN_WAITING => 'view',
            self::STATUS_ACTIVE => 'view',
            self::STATUS_STALE => 'check_dns',
            default => null,
        };
    }

    /**
     * Build the setup checklist.
     */
    protected function buildChecklist(bool $hasDmarcRecord, bool $hasMxscanRua, bool $hasReports): array
    {
        return [
            [
                'label' => 'DMARC record exists',
                'status' => $hasDmarcRecord ? 'complete' : 'incomplete',
                'icon' => $hasDmarcRecord ? 'check' : 'x',
            ],
            [
                'label' => 'MXScan RUA present',
                'status' => $hasMxscanRua ? 'complete' : 'incomplete',
                'icon' => $hasMxscanRua ? 'check' : 'x',
            ],
            [
                'label' => 'First report received',
                'status' => $hasReports ? 'complete' : 'waiting',
                'icon' => $hasReports ? 'check' : 'clock',
            ],
        ];
    }

    /**
     * Perform a fresh DNS check for DMARC configuration.
     * Updates the domain's verification state based on the canonical address only.
     *
     * @return array{
     *   success: bool,
     *   dmarc_record: string|null,
     *   has_dmarc: bool,
     *   has_rua: bool,
     *   has_mxscan_rua: bool,
     *   has_any_mxscan_rua: bool,
     *   has_canonical_mxscan_rua: bool,
     *   rua_link_state: string,
     *   message: string,
     *   recipients: list,
     *   dns_diagnostics: array
     * }
     */
    public function checkDnsAndSync(Domain $domain): array
    {
        $hostname = '_dmarc.' . $domain->domain;
        $expectedCanonical = strtolower(trim($domain->dmarc_rua_email));

        try {
            $lookup = $this->dnsLookup->lookupForDomain($domain);
            $dmarcRecord = $lookup['dmarc_record'];
            $hostname = $lookup['hostname'];

            $hasDmarc = !empty($dmarcRecord);
            $hasRua = false;
            $hasAnyMxscanRua = false;
            $hasCanonicalMxscanRua = false;
            $ruaLinkState = self::RUA_LINK_NOT_CONNECTED;
            $recipients = [];
            $parsedRua = null;
            $normalizedEmails = [];

            if ($hasDmarc) {
                $parts = $this->ruaClassifier->parseDmarcTags($dmarcRecord);
                $parsedRua = $parts['rua'] ?? null;
                $hasRua = isset($parts['rua'])
                    && count($this->ruaClassifier->parseRuaRecipients($parts['rua'])) > 0;

                $classification = $this->ruaClassifier->classify($dmarcRecord, $domain->dmarc_rua_email);
                $hasAnyMxscanRua = $classification['has_any_mxscan_rua'];
                $hasCanonicalMxscanRua = $classification['has_canonical_mxscan_rua'];
                $ruaLinkState = $classification['rua_link_state'];
                $recipients = $classification['recipients'];
                $normalizedEmails = array_values(array_map(
                    static fn (array $r): string => $r['email'],
                    $recipients
                ));
            }

            if ($hasCanonicalMxscanRua) {
                $domain->update([
                    'dmarc_rua_verified_at' => now(),
                    'dmarc_dns_record' => $dmarcRecord,
                ]);
            } else {
                $domain->update([
                    'dmarc_rua_verified_at' => null,
                    'dmarc_dns_record' => null,
                ]);
            }

            $dnsDiagnostics = [
                'hostname' => $hostname,
                'checked_at' => $lookup['checked_at']->toIso8601String(),
                'dmarc_record' => $dmarcRecord,
                'detected_rua_recipients' => $normalizedEmails,
                'expected_rua_recipient' => $expectedCanonical,
                'resolver_source' => $lookup['resolver_source'],
            ];

            Log::debug('dmarc_rua_dns_check', [
                'queried_hostname' => $hostname,
                'raw_dns_txt_response' => $lookup['raw_records'],
                'reconstructed_txt_records' => $lookup['reconstructed_txt'],
                'selected_dmarc_record' => $dmarcRecord,
                'parsed_rua_value' => $parsedRua,
                'normalized_rua_recipients' => $normalizedEmails,
                'expected_canonical_address' => $expectedCanonical,
                'domain_dmarc_token' => $domain->dmarc_token,
                'token_match_in_dns' => $hasCanonicalMxscanRua,
                'comparison_result' => [
                    'has_any_mxscan_rua' => $hasAnyMxscanRua,
                    'has_canonical_mxscan_rua' => $hasCanonicalMxscanRua,
                    'rua_link_state' => $ruaLinkState,
                ],
                'resolver_source' => $lookup['resolver_source'],
                'checked_at' => $lookup['checked_at']->toIso8601String(),
            ]);

            $message = match (true) {
                !$hasDmarc,
                !$hasRua,
                !$hasCanonicalMxscanRua => 'MXScan checked ' . $hostname . ' but did not find the expected reporting address.',
                default => 'DNS confirmed! MXScan RUA is configured. Waiting for reports (24-48 hours).',
            };

            if ($hasCanonicalMxscanRua && $domain->dmarc_last_report_at) {
                $message = 'DMARC reporting is active.';
            }

            return [
                'success' => true,
                'dmarc_record' => $dmarcRecord,
                'has_dmarc' => $hasDmarc,
                'has_rua' => (bool) $hasRua,
                'has_mxscan_rua' => $hasCanonicalMxscanRua,
                'has_any_mxscan_rua' => $hasAnyMxscanRua,
                'has_canonical_mxscan_rua' => $hasCanonicalMxscanRua,
                'rua_link_state' => $ruaLinkState,
                'message' => $message,
                'recipients' => $recipients,
                'dns_diagnostics' => $dnsDiagnostics,
            ];
        } catch (\Exception $e) {
            Log::warning('DMARC DNS check failed', [
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
            ]);

            $dnsDiagnostics = [
                'hostname' => $hostname,
                'checked_at' => now()->toIso8601String(),
                'dmarc_record' => null,
                'detected_rua_recipients' => [],
                'expected_rua_recipient' => $expectedCanonical,
                'resolver_source' => DmarcDnsLookup::RESOLVER_SOURCE,
            ];

            return [
                'success' => false,
                'dmarc_record' => null,
                'has_dmarc' => false,
                'has_rua' => false,
                'has_mxscan_rua' => false,
                'has_any_mxscan_rua' => false,
                'has_canonical_mxscan_rua' => false,
                'rua_link_state' => self::RUA_LINK_NOT_CONNECTED,
                'message' => 'MXScan checked ' . $hostname . ' but did not find the expected reporting address.',
                'recipients' => [],
                'dns_diagnostics' => $dnsDiagnostics,
            ];
        }
    }

    /**
     * Get the RUA snippet to add to an existing DMARC record.
     */
    public function getRuaSnippet(Domain $domain): string
    {
        return 'rua=mailto:' . $domain->dmarc_rua_email;
    }

    /**
     * Get a complete DMARC record suggestion for domains without DMARC.
     */
    public function getSuggestedDmarcRecord(Domain $domain): string
    {
        return "v=DMARC1; p=quarantine; rua=mailto:{$domain->dmarc_rua_email}; pct=100; adkim=r; aspf=r;";
    }

    /**
     * Get the current DMARC record from the latest finished/completed scan.
     */
    public function getCurrentDmarcRecord(Domain $domain): ?string
    {
        return $this->getDmarcRecord($domain);
    }

    /**
     * Parse a DMARC record into its components.
     */
    public function parseDmarcRecord(string $record): array
    {
        return $this->ruaClassifier->parseDmarcTags($record);
    }

    /**
     * Generate a safe updated DMARC record that preserves existing settings
     * and adds/relinks the MXScan RUA address.
     *
     * @return array{
     *   current: string,
     *   updated: string,
     *   mxscan_already_present: bool,
     *   action: string,
     *   existing_rua: string|null,
     *   removed_recipients: list<string>,
     *   preserved_recipients: list<string>,
     *   added_recipients: list<string>
     * }|null
     */
    public function getUpdatedDmarcRecord(Domain $domain): ?array
    {
        $currentRecord = $this->getCurrentDmarcRecord($domain);

        if (!$currentRecord) {
            return null;
        }

        $canonical = strtolower(trim($domain->dmarc_rua_email));
        $result = $this->ruaClassifier->rewriteRua($currentRecord, $canonical);
        $classification = $this->ruaClassifier->classify($currentRecord, $canonical);

        $removed = [];
        foreach ($classification['mxscan_recipients'] as $recipient) {
            $email = strtolower($recipient['email'] ?? '');
            if ($email !== '' && $email !== $canonical) {
                $removed[] = $email;
            }
        }
        $removed = array_values(array_unique($removed));

        $preserved = [];
        foreach ($classification['external_recipients'] as $recipient) {
            $email = strtolower($recipient['email'] ?? '');
            if ($email !== '') {
                $preserved[] = $email;
            }
        }
        $preserved = array_values(array_unique($preserved));

        $added = [];
        if (($result['action'] ?? 'none') !== 'none' && $canonical !== '') {
            $added[] = $canonical;
        }

        return [
            'current' => $result['current'],
            'updated' => $result['updated'],
            'mxscan_already_present' => $result['mxscan_already_present'],
            'action' => $result['action'],
            'existing_rua' => $result['existing_rua'],
            'removed_recipients' => $removed,
            'preserved_recipients' => $preserved,
            'added_recipients' => $added,
        ];
    }

    /**
     * Build a DMARC record string from parsed parts.
     */
    protected function buildDmarcRecord(array $parts): string
    {
        return $this->ruaClassifier->buildDmarcRecord($parts);
    }
}
