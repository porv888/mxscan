<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

final class DkimProviderSelectorResolver
{
    /**
     * @return list<string>
     */
    public function selectorsForProvider(?string $providerGuess): array
    {
        if ($providerGuess === null || $providerGuess === '') {
            return [];
        }

        $mapping = config('dkim.provider_selectors', []);
        $normalized = strtolower(trim($providerGuess));

        foreach ($mapping as $provider => $selectors) {
            if (strtolower($provider) === $normalized && is_array($selectors)) {
                return array_values(array_filter($selectors, 'is_string'));
            }
        }

        return [];
    }
}
