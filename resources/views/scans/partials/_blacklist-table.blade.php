<div class="mt-3 overflow-x-auto">
    <table class="min-w-full text-sm">
        <thead>
            <tr class="text-left text-[13px] text-gray-500">
                <th class="pb-2 pr-4">IP</th>
                <th class="pb-2 pr-4">Provider</th>
                <th class="pb-2 pr-4">Status</th>
                <th class="pb-2">Action</th>
            </tr>
        </thead>
        <tbody class="divide-y divide-gray-100">
            @forelse($rows as $r)
                <tr>
                    <td class="py-2 pr-4 font-mono text-xs">{{ $r->ip_address ?? $r['ip'] ?? 'N/A' }}</td>
                    <td class="py-2 pr-4">{{ $r->provider ?? $r['provider'] ?? 'Unknown' }}</td>
                    <td class="py-2 pr-4">
                        <x-report.status-badge :variant="($r->status ?? $r['status'] ?? '') === 'listed' ? 'danger' : 'success'" :label="ucfirst($r->status ?? $r['status'] ?? 'unknown')" />
                    </td>
                    <td class="py-2">
                        @if(!empty($r->removal_url ?? $r['removal_url'] ?? null))
                            <a class="text-sm font-medium text-blue-700 hover:underline" target="_blank" rel="noopener" href="{{ $r->removal_url ?? $r['removal_url'] }}">Delist</a>
                        @else
                            <span class="text-gray-400">—</span>
                        @endif
                    </td>
                </tr>
            @empty
                <tr><td colspan="4" class="py-3 text-center text-gray-500">No results.</td></tr>
            @endforelse
        </tbody>
    </table>
</div>
