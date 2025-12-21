{{-- Blacklist Section - Accordion (collapsed by default) --}}
<section id="blacklist" x-data="{ open: false }" class="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
  <header class="flex items-center justify-between px-4 py-3">
    <div>
      <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100">Blacklist Status</h3>
      <p class="text-sm {{ ($blacklistHits ?? 0) > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-700 dark:text-green-300' }}">
        {{ $blacklistHits ?? 0 }} listed / {{ $blacklistTotal ?? 0 }} checks
      </p>
    </div>
    <button @click="open=!open" class="text-sm text-blue-700 dark:text-blue-300 hover:underline flex items-center gap-1">
      <span x-show="!open">Show Details</span>
      <span x-show="open" x-cloak>Hide Details</span>
      <svg class="w-4 h-4 transition-transform" :class="{ 'rotate-180': open }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
      </svg>
    </button>
  </header>

  <div x-show="open" x-collapse>
    <div class="border-t border-gray-200 dark:border-gray-700 overflow-auto">
      @if($blacklistTotal > 0)
      <table class="min-w-full text-sm">
        <thead class="bg-gray-50 dark:bg-gray-800/50 text-gray-700 dark:text-gray-300">
          <tr>
            <th class="px-4 py-2 text-left font-medium">IP</th>
            <th class="px-4 py-2 text-left font-medium">Provider</th>
            <th class="px-4 py-2 text-left font-medium">Status</th>
            <th class="px-4 py-2 text-left font-medium">Action</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
        @forelse($blacklistRows as $r)
          <tr class="{{ $r->status === 'listed' ? 'bg-red-50 dark:bg-red-900/10' : '' }}">
            <td class="px-4 py-2 font-mono text-xs">{{ $r->ip_address ?? $r['ip'] ?? 'N/A' }}</td>
            <td class="px-4 py-2">{{ $r->provider ?? $r['provider'] ?? 'Unknown' }}</td>
            <td class="px-4 py-2">
              <span class="px-2 py-1 rounded-full text-xs font-medium
               {{ ($r->status ?? $r['status'] ?? '') === 'listed' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' }}">
                {{ ucfirst($r->status ?? $r['status'] ?? 'unknown') }}
              </span>
            </td>
            <td class="px-4 py-2">
              @if(!empty($r->removal_url ?? $r['removal_url'] ?? null))
                <a class="text-blue-700 dark:text-blue-300 underline text-xs" target="_blank" rel="noopener" href="{{ $r->removal_url ?? $r['removal_url'] }}">Delist</a>
              @else
                <span class="text-gray-400">—</span>
              @endif
            </td>
          </tr>
        @empty
          <tr><td colspan="4" class="px-4 py-3 text-gray-500 text-center">No results.</td></tr>
        @endforelse
        </tbody>
      </table>
      @else
      <div class="px-4 py-6 text-center text-sm text-gray-500 dark:text-gray-400">
        <p>No blacklist check performed yet.</p>
        @if(auth()->user()->can('blacklist', $domain))
        <form method="POST" action="{{ route('domains.scan.now', $domain) }}" class="mt-3 inline-block">
          @csrf
          <input type="hidden" name="mode" value="blacklist">
          <button type="submit" class="inline-flex items-center px-3 py-2 text-xs font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-600 transition-colors">
            Run Blacklist Check
          </button>
        </form>
        @else
        <div class="mt-3 text-xs text-amber-600 dark:text-amber-400">
          <a href="{{ route('pricing') }}" class="underline">Upgrade</a> to access blacklist monitoring
        </div>
        @endif
      </div>
      @endif
    </div>
  </div>
</section>
