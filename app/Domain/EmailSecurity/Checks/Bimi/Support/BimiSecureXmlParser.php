<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Support;

use DOMDocument;

final class BimiSecureXmlParser
{
    /**
     * @return array{success: bool, document: ?DOMDocument, error: ?string}
     */
    public function loadSvgString(string $svg): array
    {
        $previous = libxml_use_internal_errors(true);
        libxml_clear_errors();

        $document = new DOMDocument();
        $loaded = $document->loadXML(
            $svg,
            LIBXML_NONET | LIBXML_COMPACT | LIBXML_PARSEHUGE
        );

        $errors = libxml_get_errors();
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if (!$loaded) {
            $message = 'SVG XML is not well-formed.';
            if ($errors !== []) {
                $message = trim($errors[0]->message);
            }

            return [
                'success' => false,
                'document' => null,
                'error' => $message,
            ];
        }

        foreach ($document->childNodes as $child) {
            if ($child->nodeType === XML_DOCUMENT_TYPE_NODE) {
                return [
                    'success' => false,
                    'document' => null,
                    'error' => 'DOCTYPE declarations are not permitted in BIMI SVG.',
                ];
            }
        }

        return [
            'success' => true,
            'document' => $document,
            'error' => null,
        ];
    }
}
