<?php

namespace App\Domain\EmailSecurity\Checks\SPF;

final class SpfTerminalPolicyResolver
{
    /**
     * @param ?array{qualifier?: string, mechanism?: string} $terminalPolicy
     */
    public function resolve(?array $terminalPolicy, bool $hasExplicitAll): string
    {
        if (!$hasExplicitAll) {
            return SpfTerminalPolicy::IMPLICIT_NEUTRAL;
        }

        if ($terminalPolicy === null) {
            return SpfTerminalPolicy::UNKNOWN;
        }

        return match ($terminalPolicy['qualifier'] ?? '') {
            '-' => SpfTerminalPolicy::HARD_FAIL,
            '~' => SpfTerminalPolicy::SOFT_FAIL,
            '?' => SpfTerminalPolicy::NEUTRAL,
            '+' => SpfTerminalPolicy::PASS_ALL,
            default => SpfTerminalPolicy::UNKNOWN,
        };
    }
}
