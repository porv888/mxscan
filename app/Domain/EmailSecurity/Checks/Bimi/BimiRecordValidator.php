<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiDiscoveryResult;
use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiParsedRecord;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiUriValidator;

final class BimiRecordValidator
{
    public function __construct(
        private BimiRecordParser $parser,
        private BimiUriValidator $uriValidator,
    ) {
    }

    /**
     * @return array{
     *     valid: bool,
     *     declined: bool,
     *     parsed: ?BimiParsedRecord,
     *     errors: list<array{code: string, message: string}>,
     *     warnings: list<array{code: string, message: string}>
     * }
     */
    public function validateDiscovery(BimiDiscoveryResult $discovery): array
    {
        if ($discovery->hasDnsFailure()) {
            return [
                'valid' => false,
                'declined' => false,
                'parsed' => null,
                'errors' => [[
                    'code' => 'DNS_FAILURE',
                    'message' => $discovery->dnsError ?? 'DNS lookup failed.',
                ]],
                'warnings' => [],
            ];
        }

        if ($discovery->hasMultipleRecords()) {
            return [
                'valid' => false,
                'declined' => false,
                'parsed' => null,
                'errors' => [[
                    'code' => 'MULTIPLE_BIMI_RECORDS',
                    'message' => 'Multiple BIMI records were found.',
                ]],
                'warnings' => [],
            ];
        }

        if ($discovery->record === null) {
            return [
                'valid' => false,
                'declined' => false,
                'parsed' => null,
                'errors' => [],
                'warnings' => [],
            ];
        }

        return $this->validateParsed($this->parser->parse($discovery->record));
    }

    /**
     * @return array{
     *     valid: bool,
     *     declined: bool,
     *     parsed: BimiParsedRecord,
     *     errors: list<array{code: string, message: string}>,
     *     warnings: list<array{code: string, message: string}>
     * }
     */
    public function validateParsed(BimiParsedRecord $parsed): array
    {
        $errors = $parsed->parseErrors;
        $warnings = [];

        if ($parsed->malformed) {
            $errors[] = [
                'code' => 'MALFORMED_BIMI_RECORD',
                'message' => 'The BIMI record contains malformed tag syntax.',
            ];
        }

        if (!$parsed->versionFirst || $parsed->tag('v') !== 'BIMI1') {
            $errors[] = [
                'code' => 'INVALID_BIMI_VERSION',
                'message' => 'The BIMI record must begin with v=BIMI1.',
            ];
        }

        if (!$parsed->tagPresent('l')) {
            $errors[] = [
                'code' => 'MISSING_L_TAG',
                'message' => 'The BIMI record requires an l= tag.',
            ];
        }

        foreach ($parsed->duplicateTags as $duplicate) {
            $errors[] = [
                'code' => 'DUPLICATE_TAG',
                'message' => 'Duplicate singleton tag: ' . $duplicate,
            ];
        }

        if ($parsed->declined) {
            return [
                'valid' => true,
                'declined' => true,
                'parsed' => $parsed,
                'errors' => $errors,
                'warnings' => $warnings,
            ];
        }

        $logoUri = $parsed->tag('l');
        if ($logoUri !== null && $logoUri !== '') {
            $logoValidation = $this->uriValidator->validate($logoUri);
            if (!$logoValidation['valid']) {
                foreach ($logoValidation['errors'] as $uriError) {
                    $errors[] = [
                        'code' => 'INVALID_LOGO_URI',
                        'message' => $uriError['message'],
                    ];
                }
            }
        } elseif ($parsed->tagPresent('l')) {
            $errors[] = [
                'code' => 'EMPTY_LOGO_URI',
                'message' => 'The BIMI l= tag is present but empty without explicit declination.',
            ];
        }

        $authorityUri = $parsed->tag('a');
        if ($authorityUri !== null && $authorityUri !== '') {
            $authorityValidation = $this->uriValidator->validate($authorityUri);
            if (!$authorityValidation['valid']) {
                foreach ($authorityValidation['errors'] as $uriError) {
                    $errors[] = [
                        'code' => 'INVALID_AUTHORITY_URI',
                        'message' => $uriError['message'],
                    ];
                }
            }
        }

        $avp = $parsed->tag('avp');
        if ($avp !== null && $avp !== '' && !in_array(strtolower($avp), ['brand', 'personal'], true)) {
            $warnings[] = [
                'code' => 'INVALID_AVP',
                'message' => 'Unknown avatar preference; defaulting to brand.',
            ];
        }

        if ($parsed->tagPresent('lps') && $parsed->lpsPrefixes === [] && ($parsed->tag('lps') ?? '') !== '') {
            $errors[] = [
                'code' => 'MALFORMED_LPS',
                'message' => 'The lps tag is malformed.',
            ];
        }

        foreach ($parsed->unknownTags as $unknown) {
            $warnings[] = [
                'code' => 'UNKNOWN_EXTENSION',
                'message' => 'Unknown extension tag preserved: ' . $unknown,
            ];
        }

        return [
            'valid' => $errors === [],
            'declined' => false,
            'parsed' => $parsed,
            'errors' => $errors,
            'warnings' => $warnings,
        ];
    }
}
