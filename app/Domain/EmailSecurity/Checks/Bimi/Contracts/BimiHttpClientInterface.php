<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Contracts;

interface BimiHttpClientInterface
{
    /**
     * @return array{
     *     success: bool,
     *     url: string,
     *     http_status: ?int,
     *     content_type: ?string,
     *     body: ?string,
     *     duration_ms: int,
     *     tls_verified: bool,
     *     error: ?string,
     *     failure_category: ?string,
     *     resolved_ips: list<string>
     * }
     */
    public function fetch(string $url): array;
}
