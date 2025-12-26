<?php

namespace App\Services\Dmarc;

use Illuminate\Support\Facades\Log;
use SimpleXMLElement;
use ZipArchive;

class DmarcXmlParser
{
    /**
     * Parse a DMARC aggregate report file.
     * Supports: .xml, .zip (containing .xml), .gz (gzipped .xml)
     */
    public function parseFile(string $filePath): ?array
    {
        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

        try {
            $xmlContent = match ($extension) {
                'xml' => file_get_contents($filePath),
                'zip' => $this->extractFromZip($filePath),
                'gz' => $this->extractFromGzip($filePath),
                default => throw new \InvalidArgumentException("Unsupported file extension: {$extension}"),
            };

            if (!$xmlContent) {
                Log::warning('DmarcXmlParser: Empty XML content', ['file' => $filePath]);
                return null;
            }

            return $this->parseXml($xmlContent);
        } catch (\Throwable $e) {
            Log::error('DmarcXmlParser: Failed to parse file', [
                'file' => $filePath,
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }

    /**
     * Parse XML content string.
     */
    public function parseXml(string $xmlContent): ?array
    {
        try {
            // Suppress XML errors and handle them manually
            libxml_use_internal_errors(true);
            $xml = new SimpleXMLElement($xmlContent);
            libxml_clear_errors();

            return $this->extractReportData($xml);
        } catch (\Throwable $e) {
            Log::error('DmarcXmlParser: XML parsing failed', ['error' => $e->getMessage()]);
            return null;
        }
    }

    /**
     * Extract XML from a ZIP archive.
     */
    protected function extractFromZip(string $zipPath): ?string
    {
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            throw new \RuntimeException("Failed to open ZIP file: {$zipPath}");
        }

        $xmlContent = null;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $filename = $zip->getNameIndex($i);
            if (str_ends_with(strtolower($filename), '.xml')) {
                $xmlContent = $zip->getFromIndex($i);
                break;
            }
        }

        $zip->close();

        if (!$xmlContent) {
            throw new \RuntimeException("No XML file found in ZIP archive");
        }

        return $xmlContent;
    }

    /**
     * Extract XML from a GZIP file.
     */
    protected function extractFromGzip(string $gzPath): ?string
    {
        $content = gzdecode(file_get_contents($gzPath));
        if ($content === false) {
            throw new \RuntimeException("Failed to decompress GZIP file: {$gzPath}");
        }
        return $content;
    }

    /**
     * Extract structured data from parsed XML.
     */
    protected function extractReportData(SimpleXMLElement $xml): array
    {
        $data = [
            'report_metadata' => $this->extractReportMetadata($xml),
            'policy_published' => $this->extractPolicyPublished($xml),
            'records' => [],
        ];

        // Extract all record rows
        foreach ($xml->record as $record) {
            $data['records'][] = $this->extractRecord($record);
        }

        return $data;
    }

    /**
     * Extract report metadata.
     */
    protected function extractReportMetadata(SimpleXMLElement $xml): array
    {
        $meta = $xml->report_metadata;
        
        return [
            'org_name' => (string) ($meta->org_name ?? ''),
            'email' => (string) ($meta->email ?? ''),
            'extra_contact_info' => (string) ($meta->extra_contact_info ?? ''),
            'report_id' => (string) ($meta->report_id ?? ''),
            'date_range' => [
                'begin' => (int) ($meta->date_range->begin ?? 0),
                'end' => (int) ($meta->date_range->end ?? 0),
            ],
        ];
    }

    /**
     * Extract published policy.
     */
    protected function extractPolicyPublished(SimpleXMLElement $xml): array
    {
        $policy = $xml->policy_published;
        
        return [
            'domain' => (string) ($policy->domain ?? ''),
            'adkim' => (string) ($policy->adkim ?? 'r'), // relaxed default
            'aspf' => (string) ($policy->aspf ?? 'r'),   // relaxed default
            'p' => (string) ($policy->p ?? 'none'),
            'sp' => (string) ($policy->sp ?? ''),
            'pct' => (int) ($policy->pct ?? 100),
        ];
    }

    /**
     * Extract a single record row.
     */
    protected function extractRecord(SimpleXMLElement $record): array
    {
        $row = $record->row;
        $identifiers = $record->identifiers;
        $authResults = $record->auth_results;

        // Extract DKIM results (can be multiple)
        $dkimResults = [];
        if (isset($authResults->dkim)) {
            foreach ($authResults->dkim as $dkim) {
                $dkimResults[] = [
                    'domain' => (string) ($dkim->domain ?? ''),
                    'selector' => (string) ($dkim->selector ?? ''),
                    'result' => (string) ($dkim->result ?? ''),
                ];
            }
        }

        // Extract SPF results (can be multiple)
        $spfResults = [];
        if (isset($authResults->spf)) {
            foreach ($authResults->spf as $spf) {
                $spfResults[] = [
                    'domain' => (string) ($spf->domain ?? ''),
                    'scope' => (string) ($spf->scope ?? ''),
                    'result' => (string) ($spf->result ?? ''),
                ];
            }
        }

        // Get primary DKIM and SPF results
        $primaryDkim = $dkimResults[0] ?? ['domain' => '', 'selector' => '', 'result' => ''];
        $primarySpf = $spfResults[0] ?? ['domain' => '', 'scope' => '', 'result' => ''];

        return [
            'source_ip' => (string) ($row->source_ip ?? ''),
            'count' => (int) ($row->count ?? 1),
            'policy_evaluated' => [
                'disposition' => (string) ($row->policy_evaluated->disposition ?? 'none'),
                'dkim' => (string) ($row->policy_evaluated->dkim ?? ''),
                'spf' => (string) ($row->policy_evaluated->spf ?? ''),
            ],
            'identifiers' => [
                'header_from' => (string) ($identifiers->header_from ?? ''),
                'envelope_from' => (string) ($identifiers->envelope_from ?? ''),
                'envelope_to' => (string) ($identifiers->envelope_to ?? ''),
            ],
            'auth_results' => [
                'dkim' => $dkimResults,
                'spf' => $spfResults,
                'primary_dkim' => $primaryDkim,
                'primary_spf' => $primarySpf,
            ],
        ];
    }

    /**
     * Determine if DKIM is aligned based on policy evaluation.
     */
    public function isDkimAligned(array $record): bool
    {
        $policyDkim = strtolower($record['policy_evaluated']['dkim'] ?? '');
        return $policyDkim === 'pass';
    }

    /**
     * Determine if SPF is aligned based on policy evaluation.
     */
    public function isSpfAligned(array $record): bool
    {
        $policySpf = strtolower($record['policy_evaluated']['spf'] ?? '');
        return $policySpf === 'pass';
    }

    /**
     * Determine if record is aligned (either DKIM or SPF).
     */
    public function isAligned(array $record): bool
    {
        return $this->isDkimAligned($record) || $this->isSpfAligned($record);
    }

    /**
     * Get the primary DKIM result.
     */
    public function getDkimResult(array $record): string
    {
        return strtolower($record['auth_results']['primary_dkim']['result'] ?? '');
    }

    /**
     * Get the primary SPF result.
     */
    public function getSpfResult(array $record): string
    {
        return strtolower($record['auth_results']['primary_spf']['result'] ?? '');
    }
}
