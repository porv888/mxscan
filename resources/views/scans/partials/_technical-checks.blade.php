<section id="technical-checks" class="rounded-2xl border border-gray-200/80 bg-white shadow-sm">
    <div class="border-b border-gray-200 px-5 py-4 lg:px-6">
        <h2 class="text-xl font-semibold text-gray-900">Technical checks</h2>
        <p class="mt-1 text-sm text-gray-600">Detailed DNS, policy and transport-security evidence from the latest scan.</p>
    </div>

    @foreach($techGroups as $group)
        <div class="border-b border-gray-200 last:border-b-0">
            <div class="bg-gray-50 px-5 py-2 text-xs font-semibold uppercase tracking-wide text-gray-500 lg:px-6">{{ $group['label'] }}</div>
            @foreach($group['items'] as $row)
                <x-report.technical-check-row
                    :id="$row['id']"
                    :icon="$row['icon']"
                    :label="$row['label']"
                    :badge-variant="$row['badgeVariant']"
                    :badge-label="$row['badgeLabel']"
                    :result="$row['result']"
                    :action="$row['action'] ?? null"
                    :open="$row['open'] ?? false"
                >
                    @php $detail = $row['detail'] ?? []; @endphp

                    @if(($detail['type'] ?? '') === 'code')
                        <p class="text-sm text-gray-600">{{ $row['result'] }}</p>
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
                            <x-report.code-value
                                class="mt-3"
                                :value="$detail['value']"
                                record-type="TXT"
                                :record-host="$recordHost"
                                :copy-label="$detail['copyLabel'] ?? 'Copy record'"
                            />
                        @endif
                        @if(!empty($detail['chips']))
                            <div class="mt-3 flex flex-wrap gap-2">
                                @foreach($detail['chips'] as $chip)
                                    <span class="rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-700">{{ $chip }}</span>
                                @endforeach
                            </div>
                        @endif
                        @if(isset($detail['lookupCount']))
                            <p class="mt-3 text-sm text-gray-600">Lookup count: {{ $detail['lookupCount'] }}/{{ $detail['lookupMax'] ?? 10 }}</p>
                        @endif
                    @elseif(($detail['type'] ?? '') === 'bimi')
                        <p class="text-sm text-gray-600">{{ $row['result'] }}</p>
                        @if(!empty($detail['previewUrl']))
                            <img src="{{ $detail['previewUrl'] }}"
                                 alt="BIMI logo preview"
                                 class="mt-3 h-24 w-24 rounded-lg border border-gray-200 bg-white object-contain p-2">
                        @endif
                        @if(!empty($detail['value']))
                            <x-report.code-value
                                class="mt-3"
                                :value="$detail['value']"
                                record-type="TXT"
                                record-host="default._bimi.{{ $domain->domain }}"
                                :copy-label="$detail['copyLabel'] ?? 'Copy BIMI record'"
                            />
                        @endif
                        @if(!empty($detail['chips']))
                            <div class="mt-3 flex flex-wrap gap-2">
                                @foreach($detail['chips'] as $chip)
                                    <span class="rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-700">{{ $chip }}</span>
                                @endforeach
                            </div>
                        @endif
                    @elseif(($detail['type'] ?? '') === 'dkim')
                        <p class="text-sm text-gray-600">{{ $detail['dnsOnlyNote'] ?? '' }}</p>
                        @if(!empty($detail['selectors']))
                            <ul class="mt-3 space-y-2">
                                @foreach($detail['selectors'] as $selector)
                                    <li class="rounded-lg bg-white p-3 ring-1 ring-gray-200" x-data="{ showKey: false }">
                                        <div class="flex flex-wrap items-center justify-between gap-2">
                                            <div>
                                                <span class="text-sm font-medium text-gray-900">{{ $selector['selector'] }}</span>
                                                <p class="text-[13px] text-gray-500">{{ $selector['host'] }}</p>
                                            </div>
                                            <span class="text-[13px] text-gray-500">Public key available</span>
                                        </div>
                                        <div class="mt-2">
                                            <code class="block break-all font-mono text-xs text-gray-800" x-show="!showKey">{{ $selector['preview'] }}</code>
                                            <code class="block break-all font-mono text-xs text-gray-800" x-show="showKey" x-cloak>{{ $selector['record'] }}</code>
                                            <div class="mt-2 flex gap-2">
                                                <button type="button" class="text-sm font-medium text-blue-700 hover:underline" @click="showKey = !showKey" x-text="showKey ? 'Hide key' : 'Show key'"></button>
                                                <button type="button" class="text-sm font-medium text-gray-600 hover:underline" onclick="copyToClipboard('{{ e(addslashes($selector['record'])) }}', this)">Copy</button>
                                            </div>
                                        </div>
                                    </li>
                                @endforeach
                            </ul>
                        @endif
                    @elseif(($detail['type'] ?? '') === 'mx')
                        @if(!empty($detail['rows']))
                            <div class="overflow-x-auto">
                                <table class="min-w-full text-sm">
                                    <thead>
                                        <tr class="text-left text-[13px] text-gray-500">
                                            <th class="pb-2 pr-4">Priority</th>
                                            <th class="pb-2 pr-4">Host</th>
                                            <th class="pb-2">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        @foreach($detail['rows'] as $mxRows)
                                            <tr class="border-t border-gray-200">
                                                <td class="py-2 pr-4 font-medium text-gray-900">{{ $mxRows[0]['value'] ?? '—' }}</td>
                                                <td class="py-2 pr-4 font-mono text-xs text-gray-900">{{ $mxRows[1]['value'] ?? '—' }}</td>
                                                <td class="py-2 text-gray-600">{{ $mxRows[2]['value'] ?? '—' }}</td>
                                            </tr>
                                        @endforeach
                                    </tbody>
                                </table>
                            </div>
                        @endif
                    @elseif(($detail['type'] ?? '') === 'dmarc_reports')
                        <p class="text-sm text-gray-600">{{ $row['result'] }}</p>
                        @if(!empty($detail['visibilityUrl']))
                            <a href="{{ $detail['visibilityUrl'] }}" class="mt-3 inline-flex text-sm font-medium text-blue-700 hover:underline">Open DMARC visibility</a>
                        @endif
                        @if(!empty($detail['footer']))
                            <p class="mt-2 text-[13px] text-gray-500">{{ $detail['footer'] }}</p>
                        @endif
                    @elseif(($detail['type'] ?? '') === 'blacklist')
                        <p class="text-sm text-gray-600">{{ $detail['hits'] ?? 0 }} listed / {{ $detail['total'] ?? 0 }} checks.</p>
                        @if(($enabled['blacklist'] ?? false) && !empty($blacklistRows) && $blacklistRows->count() > 0)
                            @include('scans.partials._blacklist-table', ['rows' => $blacklistRows])
                        @endif
                    @elseif(($detail['type'] ?? '') === 'renewal')
                        <p class="text-sm text-gray-600">Domain renewal in {{ $detail['domainDays'] ?? 'unknown' }} days.</p>
                    @elseif(($detail['type'] ?? '') === 'ssl')
                        <p class="text-sm text-gray-600">SSL certificate expires in {{ $detail['sslDays'] ?? 'unknown' }} days.</p>
                    @endif
                </x-report.technical-check-row>
            @endforeach
        </div>
    @endforeach
</section>
