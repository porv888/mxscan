<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiSelectorContext;

final class BimiSelectorResolver
{
    private const SELECTOR_PATTERN = '/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,62}[a-zA-Z0-9])?$/';
    private const LOCAL_PART_PATTERN = '/^[a-z0-9._\-+]{1,64}$/';

    public function resolve(CheckContextDTO $context): BimiSelectorContext
    {
        $services = $context->enabledServices;

        if (isset($services['bimi_selector']) && is_string($services['bimi_selector']) && $services['bimi_selector'] !== '') {
            $selector = $this->validateSelector($services['bimi_selector']);

            return new BimiSelectorContext(
                value: $selector,
                source: BimiSelectorContext::SOURCE_EXPLICIT,
            );
        }

        if (isset($services['bimi_header_selector']) && is_string($services['bimi_header_selector']) && $services['bimi_header_selector'] !== '') {
            $selector = $this->validateSelector($services['bimi_header_selector']);

            return new BimiSelectorContext(
                value: $selector,
                source: BimiSelectorContext::SOURCE_HEADER,
            );
        }

        if (isset($services['bimi_provider_selector']) && is_string($services['bimi_provider_selector']) && $services['bimi_provider_selector'] !== '') {
            $selector = $this->validateSelector($services['bimi_provider_selector']);

            return new BimiSelectorContext(
                value: $selector,
                source: BimiSelectorContext::SOURCE_PROVIDER,
            );
        }

        $testLocalPart = null;
        if (isset($services['bimi_test_local_part']) && is_string($services['bimi_test_local_part']) && $services['bimi_test_local_part'] !== '') {
            $testLocalPart = $this->validateLocalPart($services['bimi_test_local_part']);
        }

        return new BimiSelectorContext(
            value: 'default',
            source: BimiSelectorContext::SOURCE_DEFAULT,
            testLocalPart: $testLocalPart,
        );
    }

    public function validateSelector(string $selector): string
    {
        $selector = strtolower(rtrim(trim($selector), '.'));

        if ($selector === '' || strlen($selector) > 63) {
            throw new \InvalidArgumentException('BIMI selector length is invalid.');
        }

        if (str_contains($selector, '..') || !preg_match(self::SELECTOR_PATTERN, $selector)) {
            throw new \InvalidArgumentException('BIMI selector syntax is invalid.');
        }

        return $selector;
    }

    public function validateLocalPart(string $localPart): string
    {
        $localPart = strtolower(trim($localPart));

        if (!preg_match(self::LOCAL_PART_PATTERN, $localPart)) {
            throw new \InvalidArgumentException('BIMI test local part syntax is invalid.');
        }

        return $localPart;
    }

    public function deriveFromLocalPart(string $localPart, array $lpsPrefixes): string
    {
        $localPart = strtolower(trim($localPart));
        $matched = 'default';

        foreach ($lpsPrefixes as $prefix) {
            $prefix = strtolower(trim($prefix));
            if ($prefix === '') {
                continue;
            }

            if (str_starts_with($localPart, $prefix)) {
                $matched = $prefix;
            }
        }

        return $this->validateSelector($matched);
    }
}
