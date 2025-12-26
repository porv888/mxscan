{{-- KPI Cards v2 - Two rows with Domain/SSL expiry --}}
@php
  $tone = fn($val, $ok=30) => $val === null ? 'gray' : ($val < 7 ? 'red' : ($val < $ok ? 'amber' : 'green'));
@endphp

<div class="mt-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
  {{-- Deliverability Score --}}
  <div class="rounded-xl border border-gray-200 dark:border-gray-700 p-4">
    <div class="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Deliverability Score</div>
    <div class="mt-2 flex items-baseline gap-2">
      <div class="text-3xl font-semibold text-gray-900 dark:text-gray-100">{{ $score ?? '—' }}<span class="text-base font-normal text-gray-500">/100</span></div>
      @isset($scoreDelta)
        <span class="text-xs px-2 py-1 rounded-full {{ ($scoreDelta ?? 0) >= 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' }}">
          {{ $scoreDelta >=0 ? '+' : '' }}{{ $scoreDelta }}
        </span>
      @endisset
    </div>
  </div>

  {{-- Blacklist --}}
  @if(($enabled['blacklist'] ?? true))
  <div class="rounded-xl border border-gray-200 dark:border-gray-700 p-4">
    <div class="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Blacklist Status</div>
    <div class="mt-2 flex items-baseline gap-2">
      @if(($blacklistHits ?? 0) > 0)
        <div class="text-2xl font-semibold text-red-600 dark:text-red-400">
          {{ $blacklistHits }} listed
        </div>
        <div class="text-sm text-gray-500">of {{ $blacklistTotal ?? 0 }} checked</div>
        <a href="#blacklist" class="ml-auto text-xs underline text-red-600 dark:text-red-400">Fix now</a>
      @else
        <div class="text-2xl font-semibold text-green-700 dark:text-green-300">
          Clean
        </div>
        <div class="text-sm text-gray-500">{{ $blacklistTotal ?? 0 }} lists checked</div>
      @endif
    </div>
  </div>
  @endif

  {{-- SPF Lookups --}}
  @if(($enabled['spf'] ?? true) || ($enabled['dns'] ?? true))
  @php 
    $spfTone = $spfLookupCount === null ? 'gray' : ($spfLookupCount >= 10 ? 'red' : ($spfLookupCount >= 7 ? 'amber' : 'green'));
    $spfStatus = $spfLookupCount === null ? 'Unknown' : ($spfLookupCount >= 10 ? 'Over limit' : ($spfLookupCount >= 7 ? 'Near limit' : 'OK'));
  @endphp
  <div class="rounded-xl border border-gray-200 dark:border-gray-700 p-4">
    <div class="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">SPF Lookups</div>
    <div class="mt-2 flex items-baseline gap-2">
      <div class="text-2xl font-semibold
        {{ $spfTone === 'red' ? 'text-red-600 dark:text-red-400' : ($spfTone === 'amber' ? 'text-amber-600 dark:text-amber-400' : 'text-green-700 dark:text-green-300') }}">
        {{ $spfStatus }}
      </div>
      <div class="text-sm text-gray-500">{{ $spfLookupCount ?? '—' }} of 10 max</div>
      @if(($spfLookupCount ?? 0) >= 7)
        <a href="#fix-pack" class="ml-auto text-xs underline">Fix SPF</a>
      @endif
    </div>
  </div>
  @endif

  {{-- DMARC --}}
  @if(($enabled['dns'] ?? true))
  <div class="rounded-xl border border-gray-200 dark:border-gray-700 p-4">
    <div class="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">DMARC Policy</div>
    <div class="mt-2 flex items-center gap-2">
      <span class="text-lg font-medium text-gray-900 dark:text-gray-100">{{ $dmarcPolicy ?? 'none' }}</span>
      @if(($dmarcAligned ?? false))
        <span class="text-xs px-2 py-1 rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">Aligned</span>
      @else
        <span class="text-xs px-2 py-1 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300">Check alignment</span>
      @endif
    </div>
  </div>
  @endif
</div>

{{-- Second row: TLS/MTA-STS + Expiries --}}
<div class="mt-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
  {{-- TLS-RPT --}}
  <div class="rounded-xl border border-gray-200 dark:border-gray-700 p-4">
    <div class="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">TLS-RPT</div>
    <div class="mt-2 flex items-baseline gap-2">
      <div class="text-lg font-medium {{ $tlsrptOk ? 'text-green-700 dark:text-green-300' : 'text-amber-600 dark:text-amber-400' }}">
        {{ $tlsrptOk ? 'Active' : 'Not set up' }}
      </div>
      @unless($tlsrptOk)
        <a href="#fix-pack" class="ml-auto text-xs underline">Add record</a>
      @endunless
    </div>
    <div class="text-xs text-gray-500 mt-1">{{ $tlsrptOk ? 'Receiving TLS failure reports' : 'Optional: Get notified of TLS issues' }}</div>
  </div>

  {{-- MTA-STS --}}
  <div class="rounded-xl border border-gray-200 dark:border-gray-700 p-4">
    <div class="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">MTA-STS</div>
    <div class="mt-2 flex items-baseline gap-2">
      <div class="text-lg font-medium {{ $mtastsOk ? 'text-green-700 dark:text-green-300' : 'text-amber-600 dark:text-amber-400' }}">
        {{ $mtastsOk ? 'Active' : 'Not set up' }}
      </div>
      @unless($mtastsOk)
        <a href="#fix-pack" class="ml-auto text-xs underline">Add policy</a>
      @endunless
    </div>
    <div class="text-xs text-gray-500 mt-1">{{ $mtastsOk ? 'Enforcing secure mail transport' : 'Optional: Enforce TLS for incoming mail' }}</div>
  </div>

  {{-- Domain Renewal --}}
  <div class="rounded-xl border border-gray-200 dark:border-gray-700 p-4">
    <div class="flex items-center justify-between">
      <div class="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Domain Renewal</div>
      @if($domain->domain_expiry_source)
        <span class="text-xs text-gray-400 dark:text-gray-500" title="Source: {{ $domain->domain_expiry_source }}&#10;Detected: {{ $domain->domain_expiry_detected_at?->diffForHumans() ?? 'Unknown' }}">
          <svg class="w-3.5 h-3.5 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </span>
      @endif
    </div>
    @php 
      $toneD = $tone($domainDays ?? null); 
      $isDetecting = $domain->domain_expiry_detected_at && $domain->domain_expiry_detected_at->diffInMinutes(now()) < 60;
    @endphp
    <div class="mt-2 flex flex-col gap-1">
      <div class="flex items-baseline gap-2">
        <div class="text-2xl font-semibold {{ $toneD==='red' ? 'text-red-600 dark:text-red-400' : ($toneD==='amber' ? 'text-amber-600 dark:text-amber-400' : ($toneD==='green' ? 'text-green-700 dark:text-green-300' : 'text-gray-500')) }}">
          {{ is_null($domainDays) ? ($isDetecting ? 'Detecting…' : '—') : $domainDays.'d' }}
        </div>
        <div class="text-sm text-gray-500">{{ $domain->domain_expires_at ? \Carbon\Carbon::parse($domain->domain_expires_at)->toDateString() : 'Not set' }}</div>
      </div>
      @if(is_null($domain->domain_expires_at) && !$isDetecting)
        <form action="{{ route('domains.expiry.refresh', $domain) }}" method="POST" class="inline">
          @csrf
          <button type="submit" class="text-xs text-blue-600 dark:text-blue-400 hover:underline">Retry now</button>
        </form>
      @endif
    </div>
  </div>

  {{-- SSL Expiry --}}
  <div class="rounded-xl border border-gray-200 dark:border-gray-700 p-4">
    <div class="flex items-center justify-between">
      <div class="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">SSL Expiry</div>
      @if($domain->ssl_expiry_source)
        <span class="text-xs text-gray-400 dark:text-gray-500" title="Source: {{ $domain->ssl_expiry_source }}&#10;Detected: {{ $domain->ssl_expiry_detected_at?->diffForHumans() ?? 'Unknown' }}">
          <svg class="w-3.5 h-3.5 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </span>
      @endif
    </div>
    @php 
      $toneS = $tone($sslDays ?? null); 
      $isDetectingSSL = $domain->ssl_expiry_detected_at && $domain->ssl_expiry_detected_at->diffInMinutes(now()) < 60;
    @endphp
    <div class="mt-2 flex flex-col gap-1">
      <div class="flex items-baseline gap-2">
        <div class="text-2xl font-semibold {{ $toneS==='red' ? 'text-red-600 dark:text-red-400' : ($toneS==='amber' ? 'text-amber-600 dark:text-amber-400' : ($toneS==='green' ? 'text-green-700 dark:text-green-300' : 'text-gray-500')) }}">
          {{ is_null($sslDays) ? ($isDetectingSSL ? 'Detecting…' : '—') : $sslDays.'d' }}
        </div>
        <div class="text-sm text-gray-500">{{ $domain->ssl_expires_at ? \Carbon\Carbon::parse($domain->ssl_expires_at)->toDateString() : 'Not set' }}</div>
      </div>
      @if(is_null($domain->ssl_expires_at) && !$isDetectingSSL)
        <form action="{{ route('domains.expiry.refresh', $domain) }}" method="POST" class="inline">
          @csrf
          <button type="submit" class="text-xs text-blue-600 dark:text-blue-400 hover:underline">Retry now</button>
        </form>
      @endif
    </div>
  </div>
</div>
