<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Monitoring;

final class BimiChangeDetector
{
    public const CHANGE_RECORD_REMOVED = 'record_removed';
    public const CHANGE_RECORD_INVALIDATED = 'record_invalidated';
    public const CHANGE_LOGO_UNAVAILABLE = 'logo_unavailable';
    public const CHANGE_LOGO_HASH_CHANGED = 'logo_hash_changed';
    public const CHANGE_SVG_REGRESSION = 'svg_regression';
    public const CHANGE_EVIDENCE_UNAVAILABLE = 'evidence_unavailable';
    public const CHANGE_CERT_EXPIRED = 'cert_expired';
    public const CHANGE_CERT_REPLACED = 'cert_replaced';
    public const CHANGE_DOMAIN_MISMATCH = 'domain_mismatch';
    public const CHANGE_DMARC_REGRESSION = 'dmarc_regression';

    /**
     * @param array<string, mixed>|null $previousAnalysis
     * @param array<string, mixed>|null $currentAnalysis
     * @return list<array<string, mixed>>
     */
    public function detectAll(?array $previousAnalysis, ?array $currentAnalysis): array
    {
        if (!is_array($previousAnalysis) || !is_array($currentAnalysis)) {
            return [];
        }

        $changes = [];

        $previousProtocol = (string) ($previousAnalysis['protocol_status'] ?? '');
        $currentProtocol = (string) ($currentAnalysis['protocol_status'] ?? '');
        if (in_array($previousProtocol, ['valid', 'declined', 'partially_evaluated'], true)
            && in_array($currentProtocol, ['none', 'permerror', 'temperror'], true)) {
            $changes[] = $this->change(self::CHANGE_RECORD_REMOVED, 'BIMI record was removed or became invalid.');
        }

        if ($previousProtocol === 'valid' && $currentProtocol === 'permerror') {
            $changes[] = $this->change(self::CHANGE_RECORD_INVALIDATED, 'BIMI record became invalid.');
        }

        $previousHash = $previousAnalysis['indicator']['sha256'] ?? null;
        $currentHash = $currentAnalysis['indicator']['sha256'] ?? null;
        if (is_string($previousHash) && is_string($currentHash) && $previousHash !== $currentHash) {
            $changes[] = $this->change(self::CHANGE_LOGO_HASH_CHANGED, 'BIMI logo hash changed.', 'changed');
        }

        if (($previousAnalysis['indicator']['status'] ?? '') === 'valid'
            && ($currentAnalysis['indicator']['status'] ?? '') !== 'valid') {
            $changes[] = $this->change(self::CHANGE_SVG_REGRESSION, 'BIMI SVG validity regressed.');
        }

        if (($previousAnalysis['indicator']['status'] ?? '') === 'valid'
            && ($currentAnalysis['indicator']['status'] ?? '') === 'unavailable') {
            $changes[] = $this->change(self::CHANGE_LOGO_UNAVAILABLE, 'BIMI logo became unavailable.', 'unavailable');
        }

        if (($previousAnalysis['authority_evidence']['status'] ?? '') === 'valid'
            && ($currentAnalysis['authority_evidence']['status'] ?? '') === 'unavailable') {
            $changes[] = $this->change(self::CHANGE_EVIDENCE_UNAVAILABLE, 'BIMI evidence document became unavailable.');
        }

        $previousFingerprint = $previousAnalysis['authority_evidence']['fingerprint_sha256'] ?? null;
        $currentFingerprint = $currentAnalysis['authority_evidence']['fingerprint_sha256'] ?? null;
        if (is_string($previousFingerprint) && is_string($currentFingerprint) && $previousFingerprint !== $currentFingerprint) {
            $changes[] = $this->change(self::CHANGE_CERT_REPLACED, 'BIMI Mark Certificate was replaced.', 'changed');
        }

        if (($previousAnalysis['authority_evidence']['days_until_expiry'] ?? 1) >= 0
            && ($currentAnalysis['authority_evidence']['days_until_expiry'] ?? 0) < 0) {
            $changes[] = $this->change(self::CHANGE_CERT_EXPIRED, 'BIMI Mark Certificate expired.');
        }

        if (($previousAnalysis['authority_evidence']['domain_match'] ?? '') !== 'mismatch'
            && ($currentAnalysis['authority_evidence']['domain_match'] ?? '') === 'mismatch') {
            $changes[] = $this->change(self::CHANGE_DOMAIN_MISMATCH, 'BIMI certificate domain mismatch detected.');
        }

        if (($previousAnalysis['dmarc_eligibility']['core_eligible'] ?? false) === true
            && ($currentAnalysis['dmarc_eligibility']['core_eligible'] ?? false) === false) {
            $changes[] = $this->change(self::CHANGE_DMARC_REGRESSION, 'DMARC eligibility for BIMI regressed.');
        }

        return $changes;
    }

    /**
     * @return array<string, mixed>
     */
    private function change(string $type, string $message, string $classification = 'unknown'): array
    {
        return [
            'change_type' => $type,
            'classification' => $classification,
            'message' => $message,
        ];
    }
}
