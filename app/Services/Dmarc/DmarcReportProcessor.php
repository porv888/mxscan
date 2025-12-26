<?php

namespace App\Services\Dmarc;

use App\Models\Domain;
use App\Models\DmarcDailyStat;
use App\Models\DmarcEvent;
use App\Models\DmarcIngest;
use App\Models\DmarcRecord;
use App\Models\DmarcReport;
use App\Models\DmarcSender;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class DmarcReportProcessor
{
    protected DmarcXmlParser $parser;

    public function __construct(DmarcXmlParser $parser)
    {
        $this->parser = $parser;
    }

    /**
     * Process a DMARC ingest record.
     */
    public function processIngest(DmarcIngest $ingest): bool
    {
        // Use Storage facade to get the correct path (respects disk root config)
        if (!Storage::disk('local')->exists($ingest->stored_path)) {
            Log::error('DmarcReportProcessor: File not found', ['path' => $ingest->stored_path]);
            $ingest->update(['status' => 'failed', 'error' => 'File not found']);
            return false;
        }
        
        $filePath = Storage::disk('local')->path($ingest->stored_path);

        $data = $this->parser->parseFile($filePath);

        if (!$data) {
            $ingest->update(['status' => 'failed', 'error' => 'Failed to parse XML']);
            return false;
        }

        try {
            $report = $this->processReportData($data, $ingest);
            
            if ($report) {
                $ingest->update(['status' => 'parsed']);
                return true;
            }
            
            return false;
        } catch (\Throwable $e) {
            Log::error('DmarcReportProcessor: Processing failed', [
                'ingest_id' => $ingest->id,
                'error' => $e->getMessage(),
            ]);
            $ingest->update(['status' => 'failed', 'error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Process parsed report data.
     */
    public function processReportData(array $data, ?DmarcIngest $ingest = null): ?DmarcReport
    {
        $metadata = $data['report_metadata'];
        $policy = $data['policy_published'];
        $records = $data['records'];

        // Find the domain by policy domain
        $policyDomain = strtolower($policy['domain']);
        $domain = Domain::where('domain', $policyDomain)->first();

        if (!$domain) {
            // Try to find by dmarc_token if we have the ingest
            if ($ingest && $ingest->message_id) {
                // Extract token from email address if possible
                $domain = $this->findDomainByToken($ingest);
            }
            
            if (!$domain) {
                Log::warning('DmarcReportProcessor: Domain not found', ['domain' => $policyDomain]);
                return null;
            }
        }

        // Generate report hash for deduplication
        $reportHash = DmarcReport::generateHash(
            $domain->id,
            $metadata['org_name'],
            $metadata['report_id'],
            $metadata['date_range']['begin'],
            $metadata['date_range']['end']
        );

        // Check for duplicate
        if (DmarcReport::where('report_hash', $reportHash)->exists()) {
            Log::info('DmarcReportProcessor: Duplicate report skipped', ['hash' => $reportHash]);
            return null;
        }

        return DB::transaction(function () use ($domain, $metadata, $policy, $records, $reportHash, $ingest) {
            // Create the report
            $report = DmarcReport::create([
                'domain_id' => $domain->id,
                'dmarc_ingest_id' => $ingest?->id,
                'org_name' => $metadata['org_name'],
                'org_email' => $metadata['email'],
                'report_id' => $metadata['report_id'],
                'date_range_begin' => Carbon::createFromTimestamp($metadata['date_range']['begin']),
                'date_range_end' => Carbon::createFromTimestamp($metadata['date_range']['end']),
                'policy_domain' => $policy['domain'],
                'policy_adkim' => $policy['adkim'],
                'policy_aspf' => $policy['aspf'],
                'policy_p' => $policy['p'],
                'policy_sp' => $policy['sp'],
                'policy_pct' => $policy['pct'],
                'report_hash' => $reportHash,
            ]);

            // Process records
            $totalCount = 0;
            $passCount = 0;
            $failCount = 0;
            $reportDate = Carbon::createFromTimestamp($metadata['date_range']['begin'])->toDateString();

            foreach ($records as $recordData) {
                $dmarcRecord = $this->createRecord($report, $domain, $recordData, $reportDate);
                
                if ($dmarcRecord) {
                    $totalCount += $dmarcRecord->count;
                    if ($dmarcRecord->aligned) {
                        $passCount += $dmarcRecord->count;
                    } else {
                        $failCount += $dmarcRecord->count;
                    }

                    // Update sender inventory
                    $this->updateSender($domain, $dmarcRecord, $metadata['org_name']);
                }
            }

            // Update report totals
            $report->update([
                'total_count' => $totalCount,
                'pass_count' => $passCount,
                'fail_count' => $failCount,
            ]);

            // Update daily stats
            $this->updateDailyStats($domain, $reportDate);

            // Update domain's last report timestamp
            $domain->update(['dmarc_last_report_at' => now()]);

            Log::info('DmarcReportProcessor: Report processed', [
                'report_id' => $report->id,
                'domain' => $domain->domain,
                'total_count' => $totalCount,
                'records' => count($records),
            ]);

            return $report;
        });
    }

    /**
     * Create a DMARC record from parsed data.
     */
    protected function createRecord(DmarcReport $report, Domain $domain, array $data, string $reportDate): ?DmarcRecord
    {
        $sourceIp = $data['source_ip'];
        $headerFrom = $data['identifiers']['header_from'];
        $disposition = $data['policy_evaluated']['disposition'];
        
        $dkimResult = $this->parser->getDkimResult($data);
        $dkimDomain = $data['auth_results']['primary_dkim']['domain'] ?? null;
        $dkimSelector = $data['auth_results']['primary_dkim']['selector'] ?? null;
        
        $spfResult = $this->parser->getSpfResult($data);
        $spfDomain = $data['auth_results']['primary_spf']['domain'] ?? null;

        $dkimAligned = $this->parser->isDkimAligned($data);
        $spfAligned = $this->parser->isSpfAligned($data);
        $aligned = $dkimAligned || $spfAligned;

        // Generate record hash
        $recordHash = DmarcRecord::generateHash(
            $sourceIp,
            $headerFrom,
            $disposition,
            $dkimResult,
            $dkimDomain,
            $spfResult,
            $spfDomain
        );

        // Check for duplicate within this report
        $existing = DmarcRecord::where('dmarc_report_id', $report->id)
            ->where('record_hash', $recordHash)
            ->first();

        if ($existing) {
            // Update count instead of creating duplicate
            $existing->increment('count', $data['count']);
            return $existing;
        }

        return DmarcRecord::create([
            'dmarc_report_id' => $report->id,
            'domain_id' => $domain->id,
            'source_ip' => $sourceIp,
            'count' => $data['count'],
            'disposition' => $disposition,
            'dkim_result' => $dkimResult ?: null,
            'dkim_domain' => $dkimDomain ?: null,
            'dkim_selector' => $dkimSelector ?: null,
            'dkim_aligned' => $dkimAligned,
            'spf_result' => $spfResult ?: null,
            'spf_domain' => $spfDomain ?: null,
            'spf_aligned' => $spfAligned,
            'header_from' => $headerFrom,
            'envelope_from' => $data['identifiers']['envelope_from'] ?? null,
            'aligned' => $aligned,
            'record_hash' => $recordHash,
            'report_date' => $reportDate,
        ]);
    }

    /**
     * Update or create sender inventory entry.
     */
    protected function updateSender(Domain $domain, DmarcRecord $record, string $orgName): void
    {
        $sender = DmarcSender::getOrCreate($domain->id, $record->source_ip);
        
        $isNewSender = $sender->wasRecentlyCreated;

        // Update aggregate counts
        $sender->total_count += $record->count;
        if ($record->aligned) {
            $sender->aligned_count += $record->count;
        }
        if ($record->isDkimPass()) {
            $sender->dkim_pass_count += $record->count;
        }
        if ($record->isSpfPass()) {
            $sender->spf_pass_count += $record->count;
        }

        // Update disposition counts
        match (strtolower($record->disposition ?? '')) {
            'none' => $sender->disposition_none += $record->count,
            'quarantine' => $sender->disposition_quarantine += $record->count,
            'reject' => $sender->disposition_reject += $record->count,
            default => null,
        };

        // Update metadata
        $sender->header_from = $sender->header_from ?: $record->header_from;
        $sender->org_name = $sender->org_name ?: $orgName;
        $sender->dkim_domain = $sender->dkim_domain ?: $record->dkim_domain;
        $sender->dkim_selector = $sender->dkim_selector ?: $record->dkim_selector;
        $sender->spf_domain = $sender->spf_domain ?: $record->spf_domain;
        $sender->last_seen_at = now();

        // Update flags
        $sender->updateFlags();

        // Create new sender event if this is a new sender with significant volume
        if ($isNewSender && $record->count >= 10) {
            DmarcEvent::createNewSenderEvent($domain, $sender, $record->count);
        }
    }

    /**
     * Update daily statistics for a domain.
     */
    protected function updateDailyStats(Domain $domain, string $date): void
    {
        // Aggregate records for this date
        $stats = DmarcRecord::where('domain_id', $domain->id)
            ->where('report_date', $date)
            ->selectRaw('
                SUM(count) as total_count,
                SUM(CASE WHEN aligned = 1 THEN count ELSE 0 END) as aligned_count,
                SUM(CASE WHEN dkim_result = "pass" THEN count ELSE 0 END) as dkim_pass_count,
                SUM(CASE WHEN spf_result = "pass" THEN count ELSE 0 END) as spf_pass_count,
                SUM(CASE WHEN disposition = "none" THEN count ELSE 0 END) as disposition_none,
                SUM(CASE WHEN disposition = "quarantine" THEN count ELSE 0 END) as disposition_quarantine,
                SUM(CASE WHEN disposition = "reject" THEN count ELSE 0 END) as disposition_reject,
                COUNT(DISTINCT source_ip) as unique_sources
            ')
            ->first();

        // Count new sources (first seen today)
        $newSources = DmarcSender::where('domain_id', $domain->id)
            ->whereDate('first_seen_at', $date)
            ->count();

        // Count reports for this date
        $reportCount = DmarcReport::where('domain_id', $domain->id)
            ->whereDate('date_range_begin', $date)
            ->count();

        $dailyStat = DmarcDailyStat::getOrCreate($domain->id, $date);
        
        $dailyStat->total_count = (int) ($stats->total_count ?? 0);
        $dailyStat->aligned_count = (int) ($stats->aligned_count ?? 0);
        $dailyStat->dkim_pass_count = (int) ($stats->dkim_pass_count ?? 0);
        $dailyStat->spf_pass_count = (int) ($stats->spf_pass_count ?? 0);
        $dailyStat->disposition_none = (int) ($stats->disposition_none ?? 0);
        $dailyStat->disposition_quarantine = (int) ($stats->disposition_quarantine ?? 0);
        $dailyStat->disposition_reject = (int) ($stats->disposition_reject ?? 0);
        $dailyStat->unique_sources = (int) ($stats->unique_sources ?? 0);
        $dailyStat->new_sources = $newSources;
        $dailyStat->report_count = $reportCount;
        
        $dailyStat->calculateRates();
        $dailyStat->save();
    }

    /**
     * Try to find domain by DMARC token from ingest.
     */
    protected function findDomainByToken(DmarcIngest $ingest): ?Domain
    {
        // This would require parsing the recipient email from the message
        // For now, return null - the domain lookup by policy_domain should work
        return null;
    }

    /**
     * Process a manually uploaded file.
     */
    public function processUploadedFile(string $filePath, Domain $domain): ?DmarcReport
    {
        $data = $this->parser->parseFile($filePath);

        if (!$data) {
            return null;
        }

        // Override the domain from the upload context
        $data['policy_published']['domain'] = $domain->domain;

        return $this->processReportData($data);
    }
}
