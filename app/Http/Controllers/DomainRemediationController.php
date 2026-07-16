<?php

namespace App\Http\Controllers;

use App\Domain\EmailSecurity\Remediation\SpfRemediationBuilder;
use App\Domain\EmailSecurity\Remediation\TechnicalRemediationBuilder;
use App\Models\Domain;
use App\Models\DomainSender;
use App\Models\Scan;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Symfony\Component\HttpFoundation\Response;

class DomainRemediationController extends Controller
{
    public function preview(Request $request, Domain $domain, SpfRemediationBuilder $builder): JsonResponse
    {
        $this->authorize('update', $domain);
        $validated = $this->validatePayload($request);

        return response()->json([
            'spf' => $builder->build(
                $domain,
                $validated['policy'] ?? '~all',
                $validated['senders'] ?? [],
                $this->existingSpfCount($domain),
            )->toArray(),
        ]);
    }

    public function save(Request $request, Domain $domain, SpfRemediationBuilder $builder): JsonResponse
    {
        $this->authorize('update', $domain);
        $validated = $this->validatePayload($request);

        DB::transaction(function () use ($domain, $validated, $request): void {
            foreach ($validated['senders'] ?? [] as $row) {
                $senderType = (string) $row['sender_type'];
                $provider = $row['provider'] ?? null;
                $mechanism = (string) $row['mechanism'];
                $value = trim((string) $row['value']);
                $fingerprint = DomainSender::fingerprint($senderType, $provider, $mechanism, $value);
                $sender = $domain->senders()->firstOrNew(['fingerprint' => $fingerprint]);
                $status = (string) $row['confirmation_status'];

                $sender->fill([
                    'sender_type' => $senderType,
                    'provider' => $provider,
                    'mechanism' => $mechanism,
                    'value' => $value,
                    'source' => $row['source'] ?? DomainSender::SOURCE_USER_ADDED,
                    'confidence' => $status === DomainSender::STATUS_CONFIRMED
                        ? DomainSender::CONFIDENCE_CONFIRMED
                        : ($row['confidence'] ?? DomainSender::CONFIDENCE_UNKNOWN),
                    'confirmation_status' => $status,
                    'confirmed_by' => $status === DomainSender::STATUS_CONFIRMED ? $request->user()->id : null,
                    'confirmed_at' => $status === DomainSender::STATUS_CONFIRMED ? now() : null,
                    'last_seen_at' => now(),
                    'is_active' => (bool) ($row['is_active'] ?? true),
                ]);
                $sender->save();
            }

            if (array_key_exists('dns_provider', $validated)) {
                $domain->update([
                    'dns_provider' => $validated['dns_provider'],
                    'dns_provider_confirmed_at' => $validated['dns_provider'] ? now() : null,
                ]);
            }
        });

        $domain->unsetRelation('senders');

        return response()->json([
            'saved' => true,
            'spf' => $builder->build(
                $domain,
                $validated['policy'] ?? '~all',
                null,
                $this->existingSpfCount($domain),
            )->toArray(),
        ]);
    }

    public function mtaStsPolicy(
        Domain $domain,
        Scan $scan,
        TechnicalRemediationBuilder $builder,
    ): Response {
        $this->authorize('view', $domain);
        abort_unless($scan->domain_id === $domain->id, 404);
        $data = $builder->build($domain, $scan, $scan->result_json ?? []);

        return response($data['mta_sts']['policy'], 200, [
            'Content-Type' => 'text/plain; charset=UTF-8',
            'Content-Disposition' => 'attachment; filename="mta-sts.txt"',
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function validatePayload(Request $request): array
    {
        return $request->validate([
            'policy' => ['nullable', Rule::in(['~all', '-all'])],
            'dns_provider' => ['nullable', Rule::in(array_keys(config('remediation.dns_providers', [])))],
            'senders' => ['present', 'array'],
            'senders.*.id' => ['nullable', 'integer'],
            'senders.*.sender_type' => ['required', Rule::in(['own_server', 'provider'])],
            'senders.*.provider' => ['nullable', 'string', Rule::in(array_keys(config('remediation.senders', [])))],
            'senders.*.mechanism' => ['required', Rule::in(['ip4', 'ip6', 'include'])],
            'senders.*.value' => ['required', 'string', 'max:512'],
            'senders.*.source' => ['nullable', Rule::in([DomainSender::SOURCE_DETECTED, DomainSender::SOURCE_USER_ADDED])],
            'senders.*.confidence' => ['nullable', Rule::in([
                DomainSender::CONFIDENCE_CONFIRMED,
                DomainSender::CONFIDENCE_LIKELY,
                DomainSender::CONFIDENCE_UNKNOWN,
            ])],
            'senders.*.confirmation_status' => ['required', Rule::in([
                DomainSender::STATUS_CONFIRMED,
                DomainSender::STATUS_REJECTED,
                DomainSender::STATUS_PENDING,
            ])],
            'senders.*.is_active' => ['nullable', 'boolean'],
        ]);
    }

    private function existingSpfCount(Domain $domain): int
    {
        $scan = $domain->scans()
            ->whereIn('status', ['finished', 'completed'])
            ->latest()
            ->first();
        $record = data_get($scan?->result_json, 'dns.records.SPF');

        return is_array($record) && ($record['status'] ?? '') === 'found' ? 1 : 0;
    }
}
