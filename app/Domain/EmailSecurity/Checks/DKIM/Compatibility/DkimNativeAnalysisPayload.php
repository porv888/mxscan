<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Compatibility;

use App\Domain\EmailSecurity\Checks\DKIM\DkimNativeResult;
use App\Domain\EmailSecurity\Checks\DKIM\DkimProtocolStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimPublicationState;
use App\Domain\EmailSecurity\Checks\DKIM\DkimStates;

final class DkimNativeAnalysisPayload
{
    public const VERSION = 'dkim-native-v1';

    /**
     * @return array<string, mixed>
     */
    public function fromNative(DkimNativeResult $native): array
    {
        return [
            'version' => self::VERSION,
            'protocol_status' => $native->protocolStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'publication_state' => $this->publicationState($native),
            'summary' => $native->summary,
            'signing_domain' => $native->signingDomain,
            'signing_verified' => $native->signingVerified,
            'selector_coverage' => $native->selectorCoverage,
            'selectors' => $native->selectors,
            'errors' => $this->sanitizeMessages($native->errors),
            'warnings' => $this->sanitizeMessages($native->warnings),
            'resolver_diagnostics' => $native->resolverDiagnostics,
        ];
    }

    /**
     * @param list<array{code?: string, message?: string}> $items
     * @return list<array{code: string, message: string}>
     */
    private function sanitizeMessages(array $items): array
    {
        return array_values(array_map(
            fn (array $item) => [
                'code' => (string) ($item['code'] ?? ''),
                'message' => (string) ($item['message'] ?? ''),
            ],
            $items,
        ));
    }

    private function publicationState(DkimNativeResult $native): string
    {
        $validSelectors = array_filter(
            $native->selectors,
            fn (array $row) => ($row['record_status'] ?? '') === 'valid',
        );

        if ($validSelectors !== []) {
            foreach ($validSelectors as $selector) {
                if (($selector['state'] ?? '') === DkimStates::FAIL) {
                    return DkimPublicationState::PUBLISHED_INVALID;
                }
            }

            return DkimPublicationState::PUBLISHED_VALID;
        }

        if ($native->protocolStatus === DkimProtocolStatus::TEMPERROR) {
            return DkimPublicationState::LOOKUP_FAILED;
        }

        if (($native->selectorCoverage['selectors_available'] ?? false) === false) {
            return DkimPublicationState::NOT_TESTED;
        }

        return DkimPublicationState::NOT_DETECTED;
    }
}
