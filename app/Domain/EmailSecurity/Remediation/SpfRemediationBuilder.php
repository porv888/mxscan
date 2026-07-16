<?php

namespace App\Domain\EmailSecurity\Remediation;

use App\Models\Domain;
use App\Models\DomainSender;

final class SpfRemediationBuilder
{
    public function __construct(
        private SpfGeneratedRecordValidator $validator,
    ) {
    }

    /**
     * @param list<array<string, mixed>>|null $senderRows
     */
    public function build(
        Domain $domain,
        string $policy = '~all',
        ?array $senderRows = null,
        int $existingSpfCount = 0,
    ): SpfRemediationResult {
        $policy = $policy === '-all' ? '-all' : '~all';
        $rows = $senderRows ?? $domain->senders()
            ->where('is_active', true)
            ->get()
            ->map(fn (DomainSender $sender) => $sender->toArray())
            ->all();

        $active = array_values(array_filter($rows, fn (array $row) => (bool) ($row['is_active'] ?? true)));
        $allResolved = $active !== [] && collect($active)->every(
            fn (array $row) => in_array(
                $row['confirmation_status'] ?? DomainSender::STATUS_PENDING,
                [DomainSender::STATUS_CONFIRMED, DomainSender::STATUS_REJECTED],
                true,
            )
        );

        $mechanisms = [];
        $inputErrors = [];
        foreach ($active as $row) {
            if (($row['confirmation_status'] ?? '') !== DomainSender::STATUS_CONFIRMED) {
                continue;
            }

            $mechanism = strtolower((string) ($row['mechanism'] ?? ''));
            $value = strtolower(trim((string) ($row['value'] ?? '')));
            if ($mechanism === 'ip4' && !filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $inputErrors[] = ['code' => 'INVALID_IPV4', 'message' => "Invalid IPv4 sender: {$value}"];
                continue;
            }
            if ($mechanism === 'ip6' && !filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $inputErrors[] = ['code' => 'INVALID_IPV6', 'message' => "Invalid IPv6 sender: {$value}"];
                continue;
            }
            if ($mechanism === 'include') {
                $provider = (string) ($row['provider'] ?? '');
                $configured = config("remediation.senders.{$provider}.include");
                if (($row['source'] ?? '') === DomainSender::SOURCE_DETECTED && $configured !== $value) {
                    $inputErrors[] = ['code' => 'UNCONFIRMED_INCLUDE', 'message' => "Provider include {$value} is not confirmed."];
                    continue;
                }
            }
            if (!in_array($mechanism, ['ip4', 'ip6', 'include'], true) || $value === '') {
                $inputErrors[] = ['code' => 'INVALID_MECHANISM', 'message' => 'A sender mechanism is invalid.'];
                continue;
            }

            $mechanisms[] = "{$mechanism}:{$value}";
        }
        $mechanisms = array_values(array_unique($mechanisms));

        if ($mechanisms === []) {
            return new SpfRemediationResult(
                state: 'Cannot generate yet',
                record: null,
                policy: '~all',
                score: 0,
                lookupCount: 0,
                errors: $inputErrors,
                warnings: [['code' => 'NO_CONFIRMED_SENDERS', 'message' => 'Confirm at least one sending service before generating SPF.']],
                mechanisms: [],
                allSendersResolved: false,
            );
        }

        if ($policy === '-all' && !$allResolved) {
            $inputErrors[] = ['code' => 'HARD_FAIL_REQUIRES_CONFIRMATION', 'message' => 'Confirm or reject every detected sender before selecting hard fail.'];
            $policy = '~all';
        }

        $record = trim('v=spf1 ' . implode(' ', $mechanisms) . ' ' . $policy);
        $validation = $this->validator->validate($domain->domain, $record, $existingSpfCount);
        $errors = array_values(array_merge($inputErrors, $validation['errors']));
        $warnings = $validation['warnings'];

        if (!$allResolved) {
            $warnings[] = ['code' => 'SENDERS_INCOMPLETE', 'message' => 'One or more detected senders still need confirmation.'];
        }

        $state = $errors === [] && $policy === '-all' && $allResolved
            ? 'Ready to publish'
            : 'Suggested starting record';

        return new SpfRemediationResult(
            state: $state,
            record: $record,
            policy: $policy,
            score: $policy === '-all' ? 20 : 15,
            lookupCount: (int) $validation['lookup_count'],
            errors: $errors,
            warnings: $warnings,
            mechanisms: $mechanisms,
            allSendersResolved: $allResolved,
        );
    }
}
