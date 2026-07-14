<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Support;

final class SpfAnalysisReader
{
    /**
     * @param array<string, mixed>|null $spf
     */
    public static function protocolStatus(?array $spf): ?string
    {
        return self::string($spf, 'protocol_status');
    }

    /**
     * @param array<string, mixed>|null $spf
     */
    public static function riskStatus(?array $spf): ?string
    {
        return self::string($spf, 'risk_status');
    }

    /**
     * @param array<string, mixed>|null $spf
     */
    public static function state(?array $spf): ?string
    {
        if ($spf === null) {
            return null;
        }

        $analysis = $spf['analysis'] ?? null;
        if (is_array($analysis) && is_string($analysis['state'] ?? null)) {
            return $analysis['state'];
        }

        return is_string($spf['ui_state'] ?? null) ? $spf['ui_state'] : null;
    }

    /**
     * @param array<string, mixed>|null $spf
     */
    public static function summary(?array $spf): ?string
    {
        return self::string($spf, 'summary');
    }

    /**
     * @param array<string, mixed>|null $spf
     */
    public static function terminalPolicy(?array $spf): ?string
    {
        if ($spf === null) {
            return null;
        }

        $analysis = $spf['analysis'] ?? null;
        if (!is_array($analysis)) {
            return null;
        }

        $value = $analysis['terminal_policy'] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param array<string, mixed>|null $spf
     */
    public static function evaluationCompleteness(?array $spf): ?string
    {
        return self::string($spf, 'evaluation_completeness');
    }

    /**
     * @param array<string, mixed>|null $spf
     * @return list<array{code: string, message: string}>
     */
    public static function errors(?array $spf): array
    {
        return self::messageList($spf, 'errors');
    }

    /**
     * @param array<string, mixed>|null $spf
     * @return list<array{code: string, message: string}>
     */
    public static function warnings(?array $spf): array
    {
        return self::messageList($spf, 'warnings');
    }

    /**
     * @param array<string, mixed>|null $spf
     * @return list<array<string, mixed>>
     */
    public static function dependencies(?array $spf): array
    {
        if ($spf === null) {
            return [];
        }

        $analysis = $spf['analysis'] ?? null;
        if (!is_array($analysis) || !is_array($analysis['dependencies'] ?? null)) {
            return [];
        }

        return $analysis['dependencies'];
    }

    /**
     * @param array<string, mixed>|null $spf
     */
    private static function string(?array $spf, string $key): ?string
    {
        if ($spf === null) {
            return null;
        }

        $analysis = $spf['analysis'] ?? null;
        if (is_array($analysis) && is_string($analysis[$key] ?? null)) {
            return $analysis[$key];
        }

        return is_string($spf[$key] ?? null) ? $spf[$key] : null;
    }

    /**
     * @param array<string, mixed>|null $spf
     * @return list<array{code: string, message: string}>
     */
    private static function messageList(?array $spf, string $key): array
    {
        if ($spf === null) {
            return [];
        }

        $analysis = $spf['analysis'] ?? null;
        if (!is_array($analysis) || !is_array($analysis[$key] ?? null)) {
            return [];
        }

        return array_values(array_map(
            fn (array $item) => [
                'code' => (string) ($item['code'] ?? ''),
                'message' => (string) ($item['message'] ?? ''),
            ],
            $analysis[$key],
        ));
    }
}
