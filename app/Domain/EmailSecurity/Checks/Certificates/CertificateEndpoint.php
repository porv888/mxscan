<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

final class CertificateEndpoint
{
    public const KIND_PRIMARY_HTTPS = 'primary_https';
    public const KIND_MTA_STS_HTTPS = 'mta_sts_https';
    public const KIND_SMTP_MX = 'smtp_mx';

    public const TRANSPORT_HTTPS = 'https';
    public const TRANSPORT_SMTP = 'smtp';

    public const PORT_HTTPS = 443;
    public const PORT_SMTP = 25;

    public function __construct(
        public readonly string $endpointKey,
        public readonly string $kind,
        public readonly string $hostname,
        public readonly int $port,
        public readonly string $transport,
        public readonly ?int $mxPriority = null,
    ) {
    }

    public static function primaryHttps(string $hostname): self
    {
        $hostname = self::normalizeHostname($hostname);

        return new self(
            endpointKey: self::KIND_PRIMARY_HTTPS . ':' . $hostname,
            kind: self::KIND_PRIMARY_HTTPS,
            hostname: $hostname,
            port: self::PORT_HTTPS,
            transport: self::TRANSPORT_HTTPS,
        );
    }

    public static function mtaStsHttps(string $domain): self
    {
        $host = 'mta-sts.' . self::normalizeHostname($domain);

        return new self(
            endpointKey: self::KIND_MTA_STS_HTTPS . ':' . $host,
            kind: self::KIND_MTA_STS_HTTPS,
            hostname: $host,
            port: self::PORT_HTTPS,
            transport: self::TRANSPORT_HTTPS,
        );
    }

    public static function smtpMx(string $hostname, int $priority = 0): self
    {
        $hostname = self::normalizeHostname($hostname);

        return new self(
            endpointKey: self::KIND_SMTP_MX . ':' . $hostname,
            kind: self::KIND_SMTP_MX,
            hostname: $hostname,
            port: self::PORT_SMTP,
            transport: self::TRANSPORT_SMTP,
            mxPriority: $priority,
        );
    }

    public static function registryKey(string $kind, string $hostname, int $port): string
    {
        return strtolower($kind) . ':' . self::normalizeHostname($hostname) . ':' . $port;
    }

    public function toRegistryKey(): string
    {
        return self::registryKey($this->kind, $this->hostname, $this->port);
    }

    public static function normalizeHostname(string $hostname): string
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));

        if ($hostname === '') {
            return '';
        }

        if (function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($hostname, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if (is_string($ascii) && $ascii !== '') {
                return strtolower($ascii);
            }
        }

        return $hostname;
    }
}
