<?php

namespace App\Domain\EmailSecurity\Checks;

use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckCollectionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use Illuminate\Support\Facades\Log;
use Throwable;

final class CheckRegistry
{
    /** @var array<string, SecurityCheckInterface> */
    private array $checksByKey = [];

    /**
     * @param iterable<SecurityCheckInterface> $checks
     */
    public function __construct(iterable $checks)
    {
        foreach ($checks as $check) {
            $key = $check->key();
            if (isset($this->checksByKey[$key])) {
                throw new \InvalidArgumentException("Duplicate security check key registered: {$key}");
            }
            $this->checksByKey[$key] = $check;
        }
    }

    public function runEnabled(
        CheckContextDTO $context,
        ?DnsCollectionResultDTO $dns,
        ScanOptionsDTO $options,
    ): CheckCollectionResultDTO {
        $results = [];
        $artifacts = [];
        $diagnostics = [];
        $priorArtifacts = [];

        foreach ($this->orderedKeys() as $key) {
            if (!$this->isEnabled($key, $options)) {
                continue;
            }

            $check = $this->checksByKey[$key];
            try {
                $execution = $check->run($context->withPriorArtifacts($priorArtifacts), $dns);
                $results[$key] = $execution->result;
                $artifacts = $this->mergeUnique($artifacts, $execution->artifacts);
                $priorArtifacts = $artifacts;
                $diagnostics = $this->mergeUnique($diagnostics, $execution->diagnostics);
            } catch (Throwable $e) {
                Log::error('Security check failed', [
                    'check' => $key,
                    'scan_id' => $context->scanId,
                    'domain' => $context->domainName,
                    'error' => $e->getMessage(),
                ]);

                throw $e;
            }
        }

        return new CheckCollectionResultDTO(
            results: $results,
            artifacts: $artifacts,
            diagnostics: $diagnostics,
        );
    }

    /**
     * @return list<string>
     */
    public function keys(): array
    {
        return array_keys($this->checksByKey);
    }

    /**
     * @param array<string, mixed> $existing
     * @param array<string, mixed> $incoming
     * @return array<string, mixed>
     */
    private function mergeUnique(array $existing, array $incoming): array
    {
        foreach ($incoming as $artifactKey => $value) {
            if (array_key_exists($artifactKey, $existing)) {
                throw new \InvalidArgumentException("Duplicate artifact key registered: {$artifactKey}");
            }
            $existing[$artifactKey] = $value;
        }

        return $existing;
    }

    /**
     * @return list<string>
     */
    private function orderedKeys(): array
    {
        $preferred = ['spf', 'dmarc', 'dkim', 'mx', 'blacklist'];
        $ordered = [];

        foreach ($preferred as $key) {
            if (isset($this->checksByKey[$key])) {
                $ordered[] = $key;
            }
        }

        foreach (array_keys($this->checksByKey) as $key) {
            if (!in_array($key, $ordered, true)) {
                $ordered[] = $key;
            }
        }

        return $ordered;
    }

    private function isEnabled(string $key, ScanOptionsDTO $options): bool
    {
        return match ($key) {
            'spf' => $options->spf,
            'dmarc' => $options->dns,
            'dkim' => $options->dns || $options->dkim,
            'mx' => $options->dns,
            'mtasts' => $options->dns,
            'tlsrpt' => $options->dns,
            'certificates' => $options->dns,
            'bimi' => $options->dns,
            'blacklist' => $options->blacklist,
            default => false,
        };
    }
}
