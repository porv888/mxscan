<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Evaluation;

use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParsedRecord;

final class DmarcPolicyEvaluator
{
    /**
     * @param array<string, mixed> $discoveryMeta
     * @return array<string, mixed>
     */
    public function evaluate(string $queriedDomain, DmarcParsedRecord $parsed, array $discoveryMeta): array
    {
        $publishedP = $parsed->tag('p');
        $publishedSp = $parsed->tag('sp');
        $publishedNp = $parsed->tag('np');
        $pct = $parsed->tag('pct');
        $effectivePct = $pct !== null ? (int) $pct : 100;
        $testingMode = ($parsed->tag('t') ?? 'n') === 'y';

        $policyDomain = $discoveryMeta['policy_domain'] ?? $queriedDomain;
        $policySource = $discoveryMeta['policy_source'] ?? 'exact';
        $isSubdomain = $queriedDomain !== $policyDomain
            && str_ends_with($queriedDomain, '.' . $policyDomain);

        $effectivePolicy = $publishedP;
        $inheritedFrom = null;

        if ($isSubdomain && $policySource !== 'exact') {
            $effectivePolicy = $publishedSp ?? $publishedNp ?? $publishedP;
            $inheritedFrom = $publishedSp !== null ? 'sp' : ($publishedNp !== null ? 'np' : 'p');
        }

        $enforcement = $this->enforcementLevel($effectivePolicy, $effectivePct, $testingMode);

        return [
            'published_p' => $publishedP,
            'published_sp' => $publishedSp,
            'published_np' => $publishedNp,
            'effective_policy' => $effectivePolicy,
            'pct' => $effectivePct,
            'testing_mode' => $testingMode,
            'enforcement' => $enforcement,
            'inherited_from' => $inheritedFrom,
            'policy_source' => $policySource,
        ];
    }

    private function enforcementLevel(?string $policy, int $pct, bool $testingMode): string
    {
        if ($testingMode) {
            return 'monitoring';
        }

        return match ($policy) {
            'none' => 'monitoring',
            'quarantine' => $pct < 100 ? 'partial_enforcement' : 'quarantine',
            'reject' => $pct < 100 ? 'partial_enforcement' : 'reject',
            default => 'invalid',
        };
    }

    /**
     * @return array{dkim: string, spf: string}
     */
    public function alignment(DmarcParsedRecord $parsed): array
    {
        return [
            'dkim' => ($parsed->tag('adkim') ?? 'r') === 's' ? 'strict' : 'relaxed',
            'spf' => ($parsed->tag('aspf') ?? 'r') === 's' ? 'strict' : 'relaxed',
        ];
    }
}
