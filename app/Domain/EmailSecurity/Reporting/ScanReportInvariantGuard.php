<?php

namespace App\Domain\EmailSecurity\Reporting;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateVerificationState;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Domain\EmailSecurity\Checks\DKIM\DkimPublicationState;
use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimAnalysisReader;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcAlignmentVerification;
use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcAnalysisReader;

final class ScanReportInvariantGuard
{
    /**
     * @param array<string, mixed> $resultData
     * @param array<string, mixed> $records
     * @param array<string, mixed> $statusCards
     * @param list<array<string, mixed>> $recommendations
     * @param list<array<string, mixed>> $scoreBreakdown
     */
    public function assertConsistent(
        ?int $score,
        array $resultData,
        array $records,
        array $statusCards,
        array $recommendations,
        array $scoreBreakdown,
        string $scanId,
    ): void {
        unset($score);

        if (!$this->hasNativeAnalysis($resultData)) {
            return;
        }

        $violations = [];

        $dkimInfo = $resultData['dkim'] ?? null;
        $dkimAnalysis = DkimAnalysisReader::analysis(is_array($dkimInfo) ? $dkimInfo : null);
        $dkimCard = $statusCards['dkim'] ?? [];
        $publicationState = is_string($dkimAnalysis['publication_state'] ?? null)
            ? $dkimAnalysis['publication_state']
            : null;

        if ($publicationState === DkimPublicationState::PUBLISHED_VALID
            && ($dkimCard['state'] ?? '') === ScanReportStatusMapper::MISSING) {
            $violations[] = 'valid DKIM key exists but status card state is missing';
        }

        if ($publicationState === DkimPublicationState::PUBLISHED_VALID && (int) ($dkimCard['count'] ?? 0) === 0) {
            $violations[] = 'valid DKIM key exists but selector list is empty in status card';
        }

        $dmarcInfo = $resultData['dmarc'] ?? null;
        $dmarcAnalysis = DmarcAnalysisReader::analysis(is_array($dmarcInfo) ? $dmarcInfo : null)
            ?? DmarcAnalysisReader::fromLegacyDnsRecord($records['DMARC'] ?? null, is_array($dmarcInfo) ? $dmarcInfo : null);
        $policy = is_array($dmarcAnalysis['policy'] ?? null)
            ? ($dmarcAnalysis['policy']['effective_policy'] ?? $dmarcAnalysis['policy']['published_p'] ?? null)
            : null;
        $enforcement = is_array($dmarcAnalysis['policy'] ?? null)
            ? ($dmarcAnalysis['policy']['enforcement'] ?? null)
            : null;

        if (in_array($policy, ['quarantine', 'reject'], true) && ($enforcement ?? '') === 'monitoring') {
            $violations[] = "DMARC p={$policy} is labeled monitoring";
        }

        $alignmentVerification = $dmarcAnalysis['alignment_verification'] ?? DmarcAlignmentVerification::NOT_VERIFIED;
        if ($alignmentVerification === DmarcAlignmentVerification::NOT_ALIGNED
            && !($resultData['dmarc_reports'] ?? false)) {
            // DNS-only scans must not claim not_aligned without report evidence.
            $violations[] = 'DMARC alignment is not_aligned without header/report evidence';
        }

        $certificatesInfo = $resultData['certificates'] ?? null;
        $certAnalysis = CertificateAnalysisReader::analysis(is_array($certificatesInfo) ? $certificatesInfo : null);
        if (is_array($certAnalysis)) {
            $overallState = (string) ($certAnalysis['state'] ?? '');
            foreach ($certAnalysis['endpoints'] ?? [] as $endpoint) {
                if (!is_array($endpoint)) {
                    continue;
                }

                $hostname = (string) ($endpoint['hostname'] ?? '');
                $presented = (string) ($endpoint['matched_identity'] ?? $endpoint['subject'] ?? $endpoint['common_name'] ?? '');
                $verificationState = (string) ($endpoint['verification_state'] ?? '');

                if ($verificationState === CertificateVerificationState::HOSTNAME_MISMATCH
                    && $hostname !== ''
                    && $presented !== ''
                    && strcasecmp($hostname, $presented) === 0) {
                    $violations[] = "certificate mismatch uses identical hostname identities for {$hostname}";
                }
            }

            $hasConfirmedMismatchRec = collect($recommendations)->contains(
                fn (array $rec) => ($rec['key'] ?? '') === 'certificates'
                    && str_contains(strtolower((string) ($rec['explanation'] ?? '')), 'does not match')
            );

            if ($overallState === 'unknown'
                && $hasConfirmedMismatchRec
                && str_contains(strtolower((string) ($certAnalysis['summary'] ?? '')), 'could not be evaluated reliably')) {
                $violations[] = 'certificate status is unable_to_verify but mismatch recommendation is confirmed';
            }
        }

        foreach ($recommendations as $recommendation) {
            if (($recommendation['scan_id'] ?? $scanId) !== $scanId) {
                $violations[] = 'technical checks and recommendations use different scan IDs';
                break;
            }
        }

        if ($violations !== []) {
            throw new ScanReportInvariantViolationException(
                'Scan report invariant violated for scan ' . $scanId . ': ' . implode('; ', $violations)
            );
        }
    }

    /**
     * @param array<string, mixed> $resultData
     */
    private function hasNativeAnalysis(array $resultData): bool
    {
        foreach (['dkim', 'dmarc', 'certificates'] as $key) {
            $analysis = $resultData[$key]['analysis'] ?? null;
            if (is_array($analysis) && ($analysis['version'] ?? null) !== null) {
                return true;
            }
        }

        return false;
    }
}

final class ScanReportInvariantViolationException extends \RuntimeException
{
}
