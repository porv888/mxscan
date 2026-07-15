<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Inspection;

final class DkimPublicKeyInspector
{
    public const TYPE_RSA = 'rsa';
    public const TYPE_ED25519 = 'ed25519';
    public const TYPE_UNKNOWN = 'unknown';

    /**
     * @return array{type: string, bits: ?int, revoked: bool, valid: bool, error: ?string}
     */
    public function inspect(string $keyType, string $publicKeyBase64): array
    {
        if ($publicKeyBase64 === '') {
            return [
                'type' => $keyType,
                'bits' => null,
                'revoked' => true,
                'valid' => false,
                'error' => 'REVOKED_KEY',
            ];
        }

        $decoded = base64_decode($publicKeyBase64, true);
        if ($decoded === false) {
            return [
                'type' => $keyType,
                'bits' => null,
                'revoked' => false,
                'valid' => false,
                'error' => 'INVALID_BASE64',
            ];
        }

        $normalizedType = strtolower($keyType ?: self::TYPE_RSA);

        if ($normalizedType === self::TYPE_ED25519 || $normalizedType === 'ed25519') {
            return $this->inspectEd25519($decoded);
        }

        if ($normalizedType === self::TYPE_RSA || $normalizedType === '') {
            return $this->inspectRsa($publicKeyBase64, $decoded);
        }

        return [
            'type' => $normalizedType,
            'bits' => null,
            'revoked' => false,
            'valid' => false,
            'error' => 'UNSUPPORTED_KEY_TYPE',
        ];
    }

    /**
     * @return array{type: string, bits: ?int, revoked: bool, valid: bool, error: ?string}
     */
    private function inspectRsa(string $publicKeyBase64, string $decoded): array
    {
        if (strlen($decoded) > 8192) {
            return [
                'type' => self::TYPE_RSA,
                'bits' => null,
                'revoked' => false,
                'valid' => false,
                'error' => 'KEY_TOO_LARGE',
            ];
        }

        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($publicKeyBase64, 64, "\n") . "-----END PUBLIC KEY-----\n";
        $resource = @openssl_pkey_get_public($pem);
        if ($resource === false) {
            return [
                'type' => self::TYPE_RSA,
                'bits' => null,
                'revoked' => false,
                'valid' => false,
                'error' => 'MALFORMED_PUBLIC_KEY',
            ];
        }

        $details = openssl_pkey_get_details($resource);
        $bits = isset($details['bits']) ? (int) $details['bits'] : null;

        return [
            'type' => self::TYPE_RSA,
            'bits' => $bits,
            'revoked' => false,
            'valid' => $bits !== null && $bits >= 1024,
            'error' => $bits !== null && $bits < 1024 ? 'RSA_TOO_WEAK' : null,
        ];
    }

    /**
     * @return array{type: string, bits: ?int, revoked: bool, valid: bool, error: ?string}
     */
    private function inspectEd25519(string $decoded): array
    {
        if (strlen($decoded) !== 32) {
            return [
                'type' => self::TYPE_ED25519,
                'bits' => 256,
                'revoked' => false,
                'valid' => false,
                'error' => 'MALFORMED_ED25519_KEY',
            ];
        }

        return [
            'type' => self::TYPE_ED25519,
            'bits' => 256,
            'revoked' => false,
            'valid' => true,
            'error' => null,
        ];
    }
}
