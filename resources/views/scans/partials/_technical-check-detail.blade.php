@props([
    'row',
    'domain',
    'blacklistRows' => null,
    'enabled' => [],
])

@php
    $detail = $row['detail'] ?? [];
    $help = $row['help'] ?? null;
@endphp

@if($help)
    <p class="text-[13px] leading-[1.5] text-gray-600">{{ $help['text'] ?? '' }}</p>
@endif

@if(($detail['type'] ?? '') === 'code')
    @if(!empty($detail['value']))
        @php
            $recordHost = match ($row['key'] ?? '') {
                'spf' => $domain->domain,
                'dmarc' => '_dmarc.' . $domain->domain,
                'tlsrpt' => '_smtp._tls.' . $domain->domain,
                'mtasts' => '_mta-sts.' . $domain->domain,
                'bimi' => 'default._bimi.' . $domain->domain,
                default => '@',
            };
        @endphp
        <div class="mt-4">
            <h4 class="text-sm font-semibold text-gray-900">Evidence</h4>
            <x-report.code-value
                class="mt-2"
                :value="$detail['value']"
                record-type="TXT"
                :record-host="$recordHost"
                :copy-label="$detail['copyLabel'] ?? 'Copy record'"
            />
        </div>
    @endif

    @if(!empty($detail['chips']))
        <div class="mt-4">
            <h4 class="text-sm font-semibold text-gray-900">Additional indicators</h4>
            <div class="mt-2 flex flex-wrap gap-2">
                @foreach($detail['chips'] as $chip)
                    <span class="mx-chip">{{ $chip }}</span>
                @endforeach
            </div>
        </div>
    @endif

    @if(isset($detail['lookupCount']))
        <p class="mt-4 text-[13px] text-gray-600">Lookup count: {{ $detail['lookupCount'] }}/{{ $detail['lookupMax'] ?? 10 }}</p>
    @endif

    @if($row['action'] ?? null)
        <div class="mt-4 border-t border-gray-200 pt-4">
            <h4 class="text-sm font-semibold text-gray-900">Recommended action</h4>
            <p class="mt-1 text-[13px] leading-[1.5] text-gray-600">{{ $help['fix'] ?? 'Review the evidence above and apply the recommended fix.' }}</p>
            <a href="{{ $row['action']['href'] ?? '#' }}" class="mt-3 inline-flex min-h-[44px] items-center mx-btn mx-btn-primary mx-btn-sm">
                {{ $row['action']['label'] }}
            </a>
        </div>
    @endif
@elseif(($detail['type'] ?? '') === 'bimi')
    @if(!empty($detail['previewUrl']))
        <img src="{{ $detail['previewUrl'] }}"
             alt="BIMI logo preview"
             class="h-24 w-24 rounded-lg border border-gray-200 bg-white object-contain p-2">
    @endif
    @if(!empty($detail['value']))
        <div class="mt-4">
            <h4 class="text-sm font-semibold text-gray-900">Evidence</h4>
            <x-report.code-value
                class="mt-2"
                :value="$detail['value']"
                record-type="TXT"
                record-host="default._bimi.{{ $domain->domain }}"
                :copy-label="$detail['copyLabel'] ?? 'Copy BIMI record'"
            />
        </div>
    @endif
    @if(!empty($detail['chips']))
        <div class="mt-4 flex flex-wrap gap-2">
            @foreach($detail['chips'] as $chip)
                <span class="mx-chip">{{ $chip }}</span>
            @endforeach
        </div>
    @endif
@elseif(($detail['type'] ?? '') === 'dkim')
    @if(!empty($detail['dnsOnlyNote']))
        <p class="text-[13px] leading-[1.5] text-gray-600">{{ $detail['dnsOnlyNote'] }}</p>
    @endif
    @if(!empty($detail['selectors']))
        <div class="mt-4">
            <h4 class="text-sm font-semibold text-gray-900">Evidence</h4>
            <ul class="mt-3 space-y-3">
                @foreach($detail['selectors'] as $selector)
                    <li class="rounded-lg border border-gray-200 bg-white p-3">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <div>
                                <span class="text-sm font-medium text-gray-900">{{ $selector['selector'] }}</span>
                                <p class="text-[13px] text-gray-500">{{ $selector['host'] }}</p>
                            </div>
                            <span class="text-[13px] text-gray-500">Public key available</span>
                        </div>
                        <div class="mt-2">
                            <x-report.dns-value-block :value="$selector['record']" :clamp="160" />
                        </div>
                    </li>
                @endforeach
            </ul>
        </div>
    @endif
@elseif(($detail['type'] ?? '') === 'mx')
    @if(!empty($detail['rows']))
        <div class="mt-1 overflow-x-auto">
            <h4 class="mb-2 text-sm font-semibold text-gray-900">Evidence</h4>
            <table class="mx-evidence-table">
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Host</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach($detail['rows'] as $mxRows)
                        <tr>
                            <td class="font-medium text-gray-900">{{ $mxRows[0]['value'] ?? '—' }}</td>
                            <td class="font-mono text-[13px] text-gray-900">{{ $mxRows[1]['value'] ?? '—' }}</td>
                            <td class="text-gray-600">{{ $mxRows[2]['value'] ?? '—' }}</td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    @endif
@elseif(($detail['type'] ?? '') === 'dmarc_reports')
    @if(!empty($detail['visibilityUrl']))
        <a href="{{ $detail['visibilityUrl'] }}" class="inline-flex min-h-[44px] items-center text-sm font-medium text-blue-700 hover:underline">Open DMARC visibility</a>
    @endif
    @if(!empty($detail['footer']))
        <p class="mt-2 text-[13px] text-gray-500">{{ $detail['footer'] }}</p>
    @endif
@elseif(($detail['type'] ?? '') === 'blacklist')
    <p class="text-[13px] leading-[1.5] text-gray-600">{{ $detail['hits'] ?? 0 }} listed / {{ $detail['total'] ?? 0 }} checks.</p>
    @if(($enabled['blacklist'] ?? false) && !empty($blacklistRows) && $blacklistRows->count() > 0)
        <div class="mt-3 overflow-x-auto rounded-lg border border-gray-200 bg-white p-3">
            @include('scans.partials._blacklist-table', ['rows' => $blacklistRows])
        </div>
    @endif
@elseif(($detail['type'] ?? '') === 'renewal')
    <p class="text-[13px] leading-[1.5] text-gray-600">Domain renewal in {{ $detail['domainDays'] ?? 'unknown' }} days.</p>
@elseif(($detail['type'] ?? '') === 'ssl')
    <p class="text-[13px] leading-[1.5] text-gray-600">SSL certificate expires in {{ $detail['sslDays'] ?? 'unknown' }} days.</p>
@endif
