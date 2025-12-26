<?php

namespace App\Services\Dmarc;

use App\Models\Domain;
use Illuminate\Support\Facades\Log;

/**
 * Unified DMARC Setup Status Evaluator
 * 
 * This service provides a single source of truth for DMARC setup status
 * across all pages: Scan page, DMARC Activity (global), and Domain DMARC Visibility page.
 */
class DmarcStatusService
{
    // Status constants - these are the 5 defined states
    public const STATUS_NOT_ENABLED = 'not_enabled';
    public const STATUS_ENABLED_NOT_MXSCAN = 'enabled_not_mxscan';
    public const STATUS_ENABLED_MXSCAN_WAITING = 'enabled_mxscan_waiting';
    public const STATUS_ACTIVE = 'active';
    public const STATUS_STALE = 'stale';

    // Default threshold for stale reports (days)
    public const DEFAULT_STALE_THRESHOLD_DAYS = 7;

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
     *   checklist: array
     * }
     */
    public function getStatus(Domain $domain, int $staleThresholdDays = self::DEFAULT_STALE_THRESHOLD_DAYS): array
    {
        // Gather all inputs for status determination
        $hasDmarcRecord = $this->hasDmarcRecord($domain);
        $hasRua = $this->hasRuaInDmarc($domain);
        $hasMxscanRua = $this->hasMxscanRua($domain);
        $hasReports = $domain->dmarc_last_report_at !== null;
        $lastReportAt = $domain->dmarc_last_report_at;
        $lastDnsCheckAt = $domain->dmarc_rua_verified_at ?? $domain->last_scanned_at;

        // Determine if reports are stale
        $isStale = false;
        if ($hasReports && $lastReportAt) {
            $isStale = $lastReportAt->lt(now()->subDays($staleThresholdDays));
        }

        // Determine status based on the decision tree
        $status = $this->determineStatus(
            $hasDmarcRecord,
            $hasRua,
            $hasMxscanRua,
            $hasReports,
            $isStale
        );

        // Build the response with all metadata
        return [
            'status' => $status,
            'label' => $this->getStatusLabel($status),
            'badge_color' => $this->getBadgeColor($status),
            'helper_text' => $this->getHelperText($status, $lastReportAt),
            'cta_text' => $this->getCtaText($status),
            'cta_action' => $this->getCtaAction($status),
            'has_dmarc_record' => $hasDmarcRecord,
            'has_rua' => $hasRua,
            'has_mxscan_rua' => $hasMxscanRua,
            'has_reports' => $hasReports,
            'is_stale' => $isStale,
            'last_report_at' => $lastReportAt,
            'last_dns_check_at' => $lastDnsCheckAt,
            'checklist' => $this->buildChecklist($hasDmarcRecord, $hasMxscanRua, $hasReports),
        ];
    }

    /**
     * Determine the status based on inputs.
     */
    protected function determineStatus(
        bool $hasDmarcRecord,
        bool $hasRua,
        bool $hasMxscanRua,
        bool $hasReports,
        bool $isStale
    ): string {
        // Status 1: Not Enabled - No DMARC TXT record exists, OR DMARC exists but no RUA at all
        if (!$hasDmarcRecord || !$hasRua) {
            return self::STATUS_NOT_ENABLED;
        }

        // Status 2: Enabled (Not to MXScan) - DMARC TXT exists, has rua, but does not include @mxscan.me
        if (!$hasMxscanRua) {
            return self::STATUS_ENABLED_NOT_MXSCAN;
        }

        // At this point, DMARC exists and includes MXScan RUA

        // Status 5: Stale - Reports exist historically, but last report older than threshold
        if ($hasReports && $isStale) {
            return self::STATUS_STALE;
        }

        // Status 4: Active - Reports exist and latest report within threshold
        if ($hasReports) {
            return self::STATUS_ACTIVE;
        }

        // Status 3: Enabled (MXScan) — Waiting for First Report
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
        
        // Check for rua= tag in the DMARC record
        return (bool) preg_match('/rua\s*=\s*mailto:/i', $dmarcRecord);
    }

    /**
     * Check if DMARC record includes MXScan RUA address.
     */
    protected function hasMxscanRua(Domain $domain): bool
    {
        // First check if we have a verified timestamp (from DNS check or scan sync)
        if ($domain->dmarc_rua_verified_at) {
            return true;
        }

        // Fall back to checking the DMARC record directly
        $dmarcRecord = $this->getDmarcRecord($domain);
        if (!$dmarcRecord) {
            return false;
        }

        // Check if our RUA address is in the DMARC record
        $ourRua = strtolower($domain->dmarc_rua_email);
        return str_contains(strtolower($dmarcRecord), $ourRua);
    }

    /**
     * Get the DMARC record from the latest scan.
     */
    protected function getDmarcRecord(Domain $domain): ?string
    {
        $latestScan = $domain->scans()->where('status', 'finished')->latest()->first();
        
        if (!$latestScan) {
            return null;
        }

        // Try facts_json first (newer format)
        $factsJson = $latestScan->facts_json;
        if (is_array($factsJson) && isset($factsJson['dmarc'])) {
            return $factsJson['dmarc'];
        }

        // Try result_json (alternative format)
        $resultJson = $latestScan->result_json;
        if (is_array($resultJson)) {
            // Check dns.records.DMARC.data format
            $dmarcData = $resultJson['dns']['records']['DMARC'] ?? $resultJson['DMARC'] ?? null;
            if ($dmarcData && isset($dmarcData['data']) && $dmarcData['status'] === 'found') {
                return $dmarcData['data'];
            }
        }

        return null;
    }

    /**
     * Get human-readable status label.
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
     * Updates the domain's verification state.
     * 
     * @return array{
     *   success: bool,
     *   dmarc_record: string|null,
     *   has_dmarc: bool,
     *   has_rua: bool,
     *   has_mxscan_rua: bool,
     *   message: string
     * }
     */
    public function checkDnsAndSync(Domain $domain): array
    {
        try {
            $dmarcRecords = dns_get_record("_dmarc.{$domain->domain}", DNS_TXT);
            $dmarcRecord = !empty($dmarcRecords) ? ($dmarcRecords[0]['txt'] ?? null) : null;

            $hasDmarc = !empty($dmarcRecord);
            $hasRua = $hasDmarc && preg_match('/rua\s*=\s*mailto:/i', $dmarcRecord);
            $hasMxscanRua = $hasRua && str_contains(strtolower($dmarcRecord), strtolower($domain->dmarc_rua_email));

            // Update verification state
            if ($hasMxscanRua && !$domain->dmarc_rua_verified_at) {
                $domain->update(['dmarc_rua_verified_at' => now()]);
            } elseif (!$hasMxscanRua && $domain->dmarc_rua_verified_at) {
                $domain->update(['dmarc_rua_verified_at' => null]);
            }

            // Determine message
            $message = match (true) {
                !$hasDmarc => 'No DMARC record found. Please add the DNS record.',
                !$hasRua => 'DMARC record found, but no RUA address configured.',
                !$hasMxscanRua => 'DMARC record found with RUA, but MXScan address not detected. Please add our RUA to your record.',
                default => 'DNS confirmed! MXScan RUA is configured. Waiting for reports (24-48 hours).',
            };

            // If we have reports, update message
            if ($hasMxscanRua && $domain->dmarc_last_report_at) {
                $message = 'DMARC reporting is active.';
            }

            return [
                'success' => true,
                'dmarc_record' => $dmarcRecord,
                'has_dmarc' => $hasDmarc,
                'has_rua' => (bool) $hasRua,
                'has_mxscan_rua' => $hasMxscanRua,
                'message' => $message,
            ];
        } catch (\Exception $e) {
            Log::warning('DMARC DNS check failed', [
                'domain' => $domain->domain,
                'error' => $e->getMessage()
            ]);

            return [
                'success' => false,
                'dmarc_record' => null,
                'has_dmarc' => false,
                'has_rua' => false,
                'has_mxscan_rua' => false,
                'message' => 'DNS check failed: ' . $e->getMessage(),
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
     * Get the current DMARC record from the latest scan.
     */
    public function getCurrentDmarcRecord(Domain $domain): ?string
    {
        $latestScan = $domain->scans()
            ->where('status', 'finished')
            ->latest()
            ->first();

        if (!$latestScan) {
            return null;
        }

        $resultJson = $latestScan->result_json ?? [];
        $records = $resultJson['dns']['records'] ?? $resultJson ?? [];
        
        if (isset($records['DMARC']) && $records['DMARC']['status'] === 'found') {
            return $records['DMARC']['data'] ?? null;
        }

        return null;
    }

    /**
     * Parse a DMARC record into its components.
     */
    public function parseDmarcRecord(string $record): array
    {
        $parts = [];
        
        // Split by semicolon and parse each tag
        $tags = preg_split('/\s*;\s*/', trim($record, '; '));
        
        foreach ($tags as $tag) {
            $tag = trim($tag);
            if (empty($tag)) continue;
            
            if (preg_match('/^([a-z]+)\s*=\s*(.+)$/i', $tag, $matches)) {
                $key = strtolower($matches[1]);
                $value = $matches[2];
                $parts[$key] = $value;
            }
        }
        
        return $parts;
    }

    /**
     * Generate a safe updated DMARC record that preserves existing settings
     * and adds/updates the MXScan RUA address.
     */
    public function getUpdatedDmarcRecord(Domain $domain): ?array
    {
        $currentRecord = $this->getCurrentDmarcRecord($domain);
        
        if (!$currentRecord) {
            return null;
        }

        $mxscanRua = $domain->dmarc_rua_email;
        $parts = $this->parseDmarcRecord($currentRecord);
        
        // Check if MXScan RUA is already present
        $existingRua = $parts['rua'] ?? '';
        $hasMxscanRua = str_contains(strtolower($existingRua), strtolower($mxscanRua));
        
        if ($hasMxscanRua) {
            return [
                'current' => $currentRecord,
                'updated' => $currentRecord,
                'mxscan_already_present' => true,
                'action' => 'none',
            ];
        }

        // Build updated RUA - append MXScan address to existing
        if (!empty($existingRua)) {
            // Existing RUA - append MXScan
            $newRua = $existingRua . ',mailto:' . $mxscanRua;
        } else {
            // No RUA - add MXScan
            $newRua = 'mailto:' . $mxscanRua;
        }
        
        $parts['rua'] = $newRua;
        
        // Rebuild the record preserving all existing tags
        $updatedRecord = $this->buildDmarcRecord($parts);
        
        return [
            'current' => $currentRecord,
            'updated' => $updatedRecord,
            'mxscan_already_present' => false,
            'action' => empty($existingRua) ? 'add_rua' : 'append_rua',
            'existing_rua' => $existingRua ?: null,
        ];
    }

    /**
     * Build a DMARC record string from parsed parts.
     */
    protected function buildDmarcRecord(array $parts): string
    {
        // Ensure v=DMARC1 comes first
        $record = 'v=DMARC1';
        unset($parts['v']);
        
        // Standard order for readability: p, sp, rua, ruf, pct, adkim, aspf, fo, rf, ri
        $order = ['p', 'sp', 'rua', 'ruf', 'pct', 'adkim', 'aspf', 'fo', 'rf', 'ri'];
        
        foreach ($order as $key) {
            if (isset($parts[$key])) {
                $record .= '; ' . $key . '=' . $parts[$key];
                unset($parts[$key]);
            }
        }
        
        // Add any remaining tags
        foreach ($parts as $key => $value) {
            $record .= '; ' . $key . '=' . $value;
        }
        
        return $record;
    }
}
