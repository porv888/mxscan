<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Macros;

use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParsedTerm;

final class SpfMacroAnalyzer
{
    private const SUPPORTED_MACROS = ['%{d}'];

    /**
     * @param list<SpfParsedTerm> $terms
     */
    public function assess(array $terms): SpfMacroAssessment
    {
        $unsupportedTokens = [];
        $affectedMechanisms = [];

        foreach ($terms as $term) {
            if (!$this->termMayContainDomainSpec($term)) {
                continue;
            }

            $value = (string) $term->argument;
            if ($value === '') {
                continue;
            }

            if (preg_match_all('/%\{[^}]+\}|%[a-zA-Z%_-]/', $value, $matches)) {
                foreach ($matches[0] as $token) {
                    if ($this->isSupportedMacroToken($token, $term->sourceDomain)) {
                        continue;
                    }
                    $unsupportedTokens[] = $token;
                    $affectedMechanisms[] = $term->name . ':' . $value;
                }
            }
        }

        $unsupportedTokens = array_values(array_unique($unsupportedTokens));
        $affectedMechanisms = array_values(array_unique($affectedMechanisms));

        return new SpfMacroAssessment(
            hasUnsupportedMacro: $unsupportedTokens !== [],
            unsupportedTokens: $unsupportedTokens,
            affectedMechanisms: $affectedMechanisms,
        );
    }

    private function termMayContainDomainSpec(SpfParsedTerm $term): bool
    {
        return in_array($term->name, ['include', 'redirect', 'exists', 'exp', 'a', 'mx'], true);
    }

    private function isSupportedMacroToken(string $token, string $sourceDomain): bool
    {
        if ($token === '%{d}') {
            return true;
        }

        if (in_array($token, self::SUPPORTED_MACROS, true)) {
            return true;
        }

        return false;
    }
}
