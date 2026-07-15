<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evaluation;

final class MxAddressClassifier
{
    public const PUBLIC = 'public';
    public const PRIVATE = 'private';
    public const LOOPBACK = 'loopback';
    public const LINK_LOCAL = 'link_local';
    public const MULTICAST = 'multicast';
    public const UNSPECIFIED = 'unspecified';
    public const DOCUMENTATION = 'documentation';
    public const RESERVED = 'reserved';
    public const INVALID = 'invalid';

    /**
     * @return array{address: string, classification: string, usable: bool}
     */
    public function classify(string $address): array
    {
        $address = trim($address);

        if ($address === '') {
            return ['address' => $address, 'classification' => self::INVALID, 'usable' => false];
        }

        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $this->classifyIpv4($address);
        }

        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return $this->classifyIpv6($address);
        }

        return ['address' => $address, 'classification' => self::INVALID, 'usable' => false];
    }

    /**
     * @return array{address: string, classification: string, usable: bool}
     */
    private function classifyIpv4(string $address): array
    {
        if ($this->inRange($address, '0.0.0.0', '0.0.0.0')) {
            return ['address' => $address, 'classification' => self::UNSPECIFIED, 'usable' => false];
        }

        if ($this->inRange($address, '127.0.0.0', '127.255.255.255')) {
            return ['address' => $address, 'classification' => self::LOOPBACK, 'usable' => false];
        }

        if ($this->inRange($address, '10.0.0.0', '10.255.255.255')
            || $this->inRange($address, '172.16.0.0', '172.31.255.255')
            || $this->inRange($address, '192.168.0.0', '192.168.255.255')) {
            return ['address' => $address, 'classification' => self::PRIVATE, 'usable' => false];
        }

        if ($this->inRange($address, '169.254.0.0', '169.254.255.255')) {
            return ['address' => $address, 'classification' => self::LINK_LOCAL, 'usable' => false];
        }

        if ($this->inRange($address, '224.0.0.0', '239.255.255.255')) {
            return ['address' => $address, 'classification' => self::MULTICAST, 'usable' => false];
        }

        if ($this->inRange($address, '192.0.2.0', '192.0.2.255')
            || $this->inRange($address, '198.51.100.0', '198.51.100.255')
            || $this->inRange($address, '203.0.113.0', '203.0.113.255')) {
            return ['address' => $address, 'classification' => self::DOCUMENTATION, 'usable' => false];
        }

        if ($this->inRange($address, '240.0.0.0', '255.255.255.254')) {
            return ['address' => $address, 'classification' => self::RESERVED, 'usable' => false];
        }

        return ['address' => $address, 'classification' => self::PUBLIC, 'usable' => true];
    }

    /**
     * @return array{address: string, classification: string, usable: bool}
     */
    private function classifyIpv6(string $address): array
    {
        $lower = strtolower($address);

        if ($lower === '::' || $lower === '0:0:0:0:0:0:0:0') {
            return ['address' => $address, 'classification' => self::UNSPECIFIED, 'usable' => false];
        }

        if (str_starts_with($lower, '::1') || str_starts_with($lower, '0:0:0:0:0:0:0:1')) {
            return ['address' => $address, 'classification' => self::LOOPBACK, 'usable' => false];
        }

        if (str_starts_with($lower, 'fe80:')) {
            return ['address' => $address, 'classification' => self::LINK_LOCAL, 'usable' => false];
        }

        if (str_starts_with($lower, 'fc') || str_starts_with($lower, 'fd')) {
            return ['address' => $address, 'classification' => self::PRIVATE, 'usable' => false];
        }

        if (str_starts_with($lower, 'ff')) {
            return ['address' => $address, 'classification' => self::MULTICAST, 'usable' => false];
        }

        if (str_starts_with($lower, '2001:db8:')) {
            return ['address' => $address, 'classification' => self::DOCUMENTATION, 'usable' => false];
        }

        return ['address' => $address, 'classification' => self::PUBLIC, 'usable' => true];
    }

    private function inRange(string $ip, string $start, string $end): bool
    {
        $ipLong = ip2long($ip);
        $startLong = ip2long($start);
        $endLong = ip2long($end);

        if ($ipLong === false || $startLong === false || $endLong === false) {
            return false;
        }

        return $ipLong >= $startLong && $ipLong <= $endLong;
    }
}
