<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evaluation;

final class SpfLookupCounter
{
    public const LIMIT = 10;

    private int $lookupCount = 0;
    private int $voidLookupCount = 0;
    private bool $attemptedOverLimit = false;

    /** @var list<array<string, mixed>> */
    private array $lookupPaths = [];

    public function requiresLookup(string $mechanism): bool
    {
        return in_array($mechanism, ['include', 'redirect', 'a', 'mx', 'ptr', 'exists'], true);
    }

    public function canIncrement(): bool
    {
        return $this->lookupCount < self::LIMIT;
    }

    public function increment(string $mechanism, string $host, string $type, ?string $parent = null): bool
    {
        if (!$this->canIncrement()) {
            $this->attemptedOverLimit = true;

            return false;
        }

        $this->lookupCount++;
        $this->lookupPaths[] = [
            'mechanism' => $mechanism,
            'host' => $host,
            'type' => $type,
            'parent' => $parent,
            'lookup_number' => $this->lookupCount,
        ];

        return true;
    }

    public function recordVoid(string $mechanism, string $host, string $type, string $reason): void
    {
        $this->voidLookupCount++;
        $this->lookupPaths[] = [
            'mechanism' => $mechanism,
            'host' => $host,
            'type' => $type,
            'void' => true,
            'reason' => $reason,
        ];
    }

    public function count(): int
    {
        return $this->lookupCount;
    }

    public function voidCount(): int
    {
        return $this->voidLookupCount;
    }

    public function remaining(): int
    {
        return max(0, self::LIMIT - $this->lookupCount);
    }

    public function atLimit(): bool
    {
        return $this->lookupCount === self::LIMIT;
    }

    public function exceeded(): bool
    {
        return $this->lookupCount > self::LIMIT;
    }

    public function attemptedOverLimit(): bool
    {
        return $this->attemptedOverLimit || $this->lookupCount > self::LIMIT;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function paths(): array
    {
        return $this->lookupPaths;
    }
}
