<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Fetch;

final class MtaStsPolicyFetchResult
{
    public const STATUS_SUCCESS = 'success';
    public const STATUS_DNS_FAILURE = 'dns_failure';
    public const STATUS_CONNECTION_TIMEOUT = 'connection_timeout';
    public const STATUS_TLS_HANDSHAKE_FAILURE = 'tls_handshake_failure';
    public const STATUS_CERTIFICATE_FAILURE = 'certificate_failure';
    public const STATUS_HTTP_NON_200 = 'http_non_200';
    public const STATUS_REDIRECT = 'redirect_response';
    public const STATUS_BODY_TOO_LARGE = 'body_too_large';
    public const STATUS_MALFORMED_BODY = 'malformed_body';

    public function __construct(
        public readonly string $url,
        public readonly string $status,
        public readonly ?int $httpStatus = null,
        public readonly ?string $contentType = null,
        public readonly ?string $body = null,
        public readonly ?int $durationMs = null,
        public readonly ?string $failureCategory = null,
        public readonly ?string $bodyPreview = null,
    ) {
    }

    public function isSuccess(): bool
    {
        return $this->status === self::STATUS_SUCCESS;
    }
}
