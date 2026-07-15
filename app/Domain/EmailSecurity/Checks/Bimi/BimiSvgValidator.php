<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiSecureXmlParser;
use DOMElement;

final class BimiSvgValidator
{
    private const FORBIDDEN_ELEMENTS = [
        'script', 'foreignobject', 'use', 'iframe', 'animate', 'animatemotion',
        'animatetransform', 'set', 'image',
    ];

    public function __construct(
        private BimiSecureXmlParser $xmlParser,
    ) {
    }

    /**
     * @return array{
     *     valid: bool,
     *     tiny_ps_valid: bool,
     *     bytes: int,
     *     validation_errors: list<array{code: string, message: string}>,
     *     validation_warnings: list<array{code: string, message: string}>,
     *     diagnostics: array<string, mixed>
     * }
     */
    public function validate(string $svgBytes): array
    {
        $maxBytes = (int) config('bimi.svg_max_bytes', 32768);
        $maxElements = (int) config('bimi.svg_max_elements', 500);
        $maxDepth = (int) config('bimi.svg_max_depth', 32);

        $errors = [];
        $warnings = [];
        $bytes = strlen($svgBytes);

        if ($bytes > $maxBytes) {
            $errors[] = [
                'code' => 'SVG_TOO_LARGE',
                'message' => 'SVG exceeds maximum allowed uncompressed size.',
            ];
        }

        if (preg_match('/<!DOCTYPE/i', $svgBytes) === 1) {
            $errors[] = [
                'code' => 'DOCTYPE_FORBIDDEN',
                'message' => 'DOCTYPE declarations are not permitted.',
            ];
        }

        if (preg_match('/<!ENTITY/i', $svgBytes) === 1) {
            $errors[] = [
                'code' => 'ENTITY_FORBIDDEN',
                'message' => 'Entity declarations are not permitted.',
            ];
        }

        if (stripos($svgBytes, 'javascript:') !== false) {
            $errors[] = [
                'code' => 'JAVASCRIPT_URI',
                'message' => 'javascript: URIs are not permitted.',
            ];
        }

        foreach (self::FORBIDDEN_ELEMENTS as $element) {
            if (preg_match('/<' . preg_quote($element, '/') . '\b/i', $svgBytes) === 1) {
                $errors[] = [
                    'code' => 'FORBIDDEN_ELEMENT',
                    'message' => 'Forbidden SVG element: ' . $element,
                ];
            }
        }

        if (preg_match('/\son[a-z]+\s*=/i', $svgBytes) === 1) {
            $errors[] = [
                'code' => 'EVENT_HANDLER',
                'message' => 'Event handler attributes are not permitted.',
            ];
        }

        if (preg_match('/xlink:href\s*=\s*["\']https?:/i', $svgBytes) === 1) {
            $errors[] = [
                'code' => 'EXTERNAL_REFERENCE',
                'message' => 'External xlink:href references are not permitted.',
            ];
        }

        $parsed = $this->xmlParser->loadSvgString($svgBytes);
        if (!$parsed['success'] || $parsed['document'] === null) {
            $errors[] = [
                'code' => 'MALFORMED_XML',
                'message' => $parsed['error'] ?? 'SVG is not well-formed XML.',
            ];

            return $this->result(false, false, $bytes, $errors, $warnings, []);
        }

        $document = $parsed['document'];
        $svgElements = $document->getElementsByTagName('svg');
        if ($svgElements->length === 0) {
            $errors[] = [
                'code' => 'MISSING_SVG_ROOT',
                'message' => 'SVG root element is required.',
            ];
        } else {
            /** @var DOMElement $root */
            $root = $svgElements->item(0);
            $version = $root->getAttribute('version');
            $baseProfile = $root->getAttribute('baseProfile');

            if ($version !== '1.2') {
                $errors[] = [
                    'code' => 'INVALID_SVG_VERSION',
                    'message' => 'SVG version must be 1.2.',
                ];
            }

            if (strtolower($baseProfile) !== 'tiny-ps') {
                $errors[] = [
                    'code' => 'INVALID_BASE_PROFILE',
                    'message' => 'SVG baseProfile must be tiny-ps.',
                ];
            }

            $viewBox = $root->getAttribute('viewBox');
            if ($viewBox !== '') {
                $parts = preg_split('/\s+/', trim($viewBox)) ?: [];
                if (count($parts) === 4) {
                    $width = (float) $parts[2];
                    $height = (float) $parts[3];
                    if ($width > 0 && $height > 0 && abs($width - $height) > 0.01) {
                        $warnings[] = [
                            'code' => 'NON_SQUARE_VIEWBOX',
                            'message' => 'SVG viewBox is not square.',
                        ];
                    }
                }
            }
        }

        $titles = $document->getElementsByTagName('title');
        if ($titles->length === 0 || trim($titles->item(0)?->textContent ?? '') === '') {
            $errors[] = [
                'code' => 'MISSING_TITLE',
                'message' => 'SVG title element is required and must be non-empty.',
            ];
        }

        $elementCount = $document->getElementsByTagName('*')->length;
        if ($elementCount > $maxElements) {
            $errors[] = [
                'code' => 'TOO_MANY_ELEMENTS',
                'message' => 'SVG exceeds maximum element count.',
            ];
        }

        $depth = $this->maxDepth($document->documentElement);
        if ($depth > $maxDepth) {
            $errors[] = [
                'code' => 'TOO_DEEP',
                'message' => 'SVG exceeds maximum nesting depth.',
            ];
        }

        $tinyPsValid = $errors === [];

        return $this->result($tinyPsValid, $tinyPsValid, $bytes, $errors, $warnings, [
            'element_count' => $elementCount,
            'max_depth' => $depth,
        ]);
    }

    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param array<string, mixed> $diagnostics
     * @return array{
     *     valid: bool,
     *     tiny_ps_valid: bool,
     *     bytes: int,
     *     validation_errors: list<array{code: string, message: string}>,
     *     validation_warnings: list<array{code: string, message: string}>,
     *     diagnostics: array<string, mixed>
     * }
     */
    private function result(
        bool $valid,
        bool $tinyPsValid,
        int $bytes,
        array $errors,
        array $warnings,
        array $diagnostics,
    ): array {
        return [
            'valid' => $valid,
            'tiny_ps_valid' => $tinyPsValid,
            'bytes' => $bytes,
            'validation_errors' => $errors,
            'validation_warnings' => $warnings,
            'diagnostics' => $diagnostics,
        ];
    }

    private function maxDepth(?\DOMNode $node, int $current = 0): int
    {
        if ($node === null) {
            return $current;
        }

        $max = $current;
        foreach ($node->childNodes as $child) {
            if ($child instanceof \DOMElement) {
                $max = max($max, $this->maxDepth($child, $current + 1));
            }
        }

        return $max;
    }
}
