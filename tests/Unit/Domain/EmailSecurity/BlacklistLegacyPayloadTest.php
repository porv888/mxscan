<?php

namespace Tests\Unit\Domain\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistReputationStatus;
use App\Domain\EmailSecurity\Checks\Blacklist\Compatibility\BlacklistLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistNativeResult;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistAnalysisStatus;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistStates;
use App\Domain\EmailSecurity\Checks\Blacklist\Support\BlacklistAnalysisReader;
use Tests\TestCase;

class BlacklistLegacyPayloadTest extends TestCase
{
    public function test_zero_results_is_not_clean(): void
    {
        $native = $this->nativeNotChecked();
        $payload = (new BlacklistLegacyPayloadAdapter())->toResultJsonBlacklist($native);

        $this->assertSame(0, $payload['total_checks']);
        $this->assertFalse($payload['is_clean']);
        $this->assertSame(BlacklistReputationStatus::NOT_CHECKED, $payload['analysis']['reputation_status']);
    }

    public function test_complete_clean_payload(): void
    {
        $native = new BlacklistNativeResult(
            domain: 'example.test',
            analysisStatus: BlacklistAnalysisStatus::COMPLETE,
            reputationStatus: BlacklistReputationStatus::CLEAN,
            state: BlacklistStates::PASS,
            summary: 'clean',
            evaluationCompleteness: 'complete',
            mxEvidenceVersion: 'mx-native-v1',
            targets: [],
            providers: [],
            checks: [],
            targetResults: [],
            providerHealth: [],
            listings: [],
            counts: [
                'queries_planned' => 2,
                'usable_results' => 2,
                'listed_results' => 0,
                'clean_results' => 2,
                'providers_enabled' => 2,
                'targets_total' => 1,
                'ipv4_targets' => 1,
                'ipv6_targets' => 0,
            ],
        );

        $payload = (new BlacklistLegacyPayloadAdapter())->toResultJsonBlacklist($native);
        $this->assertTrue($payload['is_clean']);
        $this->assertSame(2, $payload['total_checks']);
        $this->assertSame(2, $payload['ok_count']);
    }

    public function test_listed_results_are_not_clean(): void
    {
        $native = new BlacklistNativeResult(
            domain: 'example.test',
            analysisStatus: BlacklistAnalysisStatus::PARTIAL,
            reputationStatus: BlacklistReputationStatus::LISTED,
            state: BlacklistStates::FAIL,
            summary: 'listed',
            evaluationCompleteness: 'partial',
            mxEvidenceVersion: 'mx-native-v1',
            targets: [],
            providers: [],
            checks: [],
            targetResults: [],
            providerHealth: [],
            listings: [['provider_key' => 'spamhaus_zen']],
            counts: [
                'queries_planned' => 2,
                'usable_results' => 2,
                'listed_results' => 1,
                'clean_results' => 1,
            ],
        );

        $payload = (new BlacklistLegacyPayloadAdapter())->toResultJsonBlacklist($native);
        $this->assertFalse($payload['is_clean']);
        $this->assertSame(1, $payload['listed_count']);
    }

    public function test_facts_contract_requires_was_checked_for_usable_results(): void
    {
        $payload = (new BlacklistLegacyPayloadAdapter())->toResultJsonBlacklist($this->nativeClean());
        $facts = BlacklistAnalysisReader::facts($payload);

        $this->assertTrue($facts['blacklist_was_checked']);
        $this->assertSame('clean', $facts['blacklist_status']);
        $this->assertArrayHasKey('blacklist_reputation_status', $facts);
    }

    private function nativeNotChecked(): BlacklistNativeResult
    {
        return new BlacklistNativeResult(
            domain: 'example.test',
            analysisStatus: BlacklistAnalysisStatus::NOT_CHECKED,
            reputationStatus: BlacklistReputationStatus::NOT_CHECKED,
            state: BlacklistStates::NOT_CHECKED,
            summary: 'not checked',
            evaluationCompleteness: 'not_applicable',
            mxEvidenceVersion: null,
            targets: [],
            providers: [],
            checks: [],
            targetResults: [],
            providerHealth: [],
            listings: [],
            counts: [
                'queries_planned' => 0,
                'usable_results' => 0,
                'listed_results' => 0,
                'clean_results' => 0,
            ],
        );
    }

    private function nativeClean(): BlacklistNativeResult
    {
        return new BlacklistNativeResult(
            domain: 'example.test',
            analysisStatus: BlacklistAnalysisStatus::COMPLETE,
            reputationStatus: BlacklistReputationStatus::CLEAN,
            state: BlacklistStates::PASS,
            summary: 'clean',
            evaluationCompleteness: 'complete',
            mxEvidenceVersion: 'mx-native-v1',
            targets: [],
            providers: [],
            checks: [],
            targetResults: [],
            providerHealth: [],
            listings: [],
            counts: [
                'queries_planned' => 6,
                'usable_results' => 6,
                'listed_results' => 0,
                'clean_results' => 6,
                'providers_enabled' => 6,
                'targets_total' => 1,
                'ipv4_targets' => 1,
            ],
        );
    }
}
