@props([
    'row',
    'domain',
    'blacklistRows' => null,
    'enabled' => [],
])

@php
    $detail = $row['detail'] ?? [];
    $help = $row['help'] ?? null;
    $key = $row['key'] ?? '';
@endphp

@if(in_array($row['presentationState'] ?? 'passing', ['failing', 'optional'], true))
    @include('scans.partials._technical-check-remediation', [
        'row' => $row,
        'domain' => $domain,
        'scan' => $scan,
        'technicalRemediation' => $technicalRemediation ?? [],
    ])
@elseif(($detail['type'] ?? '') === 'code')
    @if($key === 'spf')
        <div class="mx-tech-detail-sections">
            <div class="mx-tech-detail-block">
                <h4 class="mx-tech-detail-heading">Why this matters</h4>
                <p class="mx-tech-detail-text">SPF identifies which services may send email for this domain.</p>
            </div>

            @if(!empty($detail['value']))
                <div class="mx-tech-detail-block">
                    <h4 class="mx-tech-detail-heading">Evidence</h4>
                    <x-report.code-value
                        :value="$detail['value']"
                        record-type="TXT"
                        :record-host="$domain->domain"
                        :copy-label="$detail['copyLabel'] ?? 'Copy record'"
                    />
                    @if(isset($detail['lookupCount']))
                        <p class="mt-2 text-[13px] text-gray-600">Lookup count: {{ $detail['lookupCount'] }}/{{ $detail['lookupMax'] ?? 10 }}</p>
                    @endif
                </div>
            @endif

            @if(($row['badgeLabel'] ?? '') === 'Missing' || ($row['action'] ?? null))
                <div class="mx-tech-detail-block">
                    <h4 class="mx-tech-detail-heading">Recommended action</h4>
                    <p class="mx-tech-detail-text">Publish one SPF TXT record containing every authorized sending service.</p>
                    <a href="#what-to-fix" class="mx-tech-detail-link">View fix instructions</a>
                </div>
            @endif
        </div>
    @else
        @if($help)
            <div class="mx-tech-detail-block">
                <h4 class="mx-tech-detail-heading">Why this matters</h4>
                <p class="mx-tech-detail-text">{{ $help['text'] ?? '' }}</p>
            </div>
        @endif

        @if(!empty($detail['value']))
            @php
                $recordHost = match ($key) {
                    'dmarc' => '_dmarc.' . $domain->domain,
                    'tlsrpt' => '_smtp._tls.' . $domain->domain,
                    'mtasts' => '_mta-sts.' . $domain->domain,
                    'bimi' => 'default._bimi.' . $domain->domain,
                    default => '@',
                };
            @endphp
            <div class="mx-tech-detail-block">
                <h4 class="mx-tech-detail-heading">Evidence</h4>
                <x-report.code-value
                    :value="$detail['value']"
                    record-type="TXT"
                    :record-host="$recordHost"
                    :copy-label="$detail['copyLabel'] ?? 'Copy record'"
                />
            </div>
        @endif

        @if(!empty($detail['chips']))
            <div class="mx-tech-detail-block">
                <div class="flex flex-wrap gap-2">
                    @foreach($detail['chips'] as $chip)
                        <span class="mx-chip">{{ $chip }}</span>
                    @endforeach
                </div>
            </div>
        @endif

        @if(($row['action'] ?? null) && !str_starts_with($row['action']['href'] ?? '', '#'))
            <div class="mx-tech-detail-block">
                <h4 class="mx-tech-detail-heading">Recommended action</h4>
                <p class="mx-tech-detail-text">{{ $help['fix'] ?? 'Review the evidence above and apply the recommended fix.' }}</p>
                <a href="{{ $row['action']['href'] }}" class="mx-tech-detail-link">{{ $row['action']['label'] }}</a>
            </div>
        @elseif(($row['action'] ?? null) && str_starts_with($row['action']['href'] ?? '', '#'))
            <div class="mx-tech-detail-block">
                <h4 class="mx-tech-detail-heading">Recommended action</h4>
                <p class="mx-tech-detail-text">{{ $help['fix'] ?? 'Review the evidence above and apply the recommended fix.' }}</p>
                <a href="{{ $row['action']['href'] }}" class="mx-tech-detail-link">View fix instructions</a>
            </div>
        @endif
    @endif
@elseif(($detail['type'] ?? '') === 'bimi')
    @if($help)
        <div class="mx-tech-detail-block">
            <h4 class="mx-tech-detail-heading">Why this matters</h4>
            <p class="mx-tech-detail-text">{{ $help['text'] ?? '' }}</p>
        </div>
    @endif
    @if(!empty($detail['previewUrl']))
        <img src="{{ $detail['previewUrl'] }}"
             alt="BIMI logo preview"
             class="h-20 w-20 rounded-lg border border-gray-200 bg-white object-contain p-2">
    @endif
    @if(!empty($detail['value']))
        <div class="mx-tech-detail-block">
            <h4 class="mx-tech-detail-heading">Evidence</h4>
            <x-report.code-value
                :value="$detail['value']"
                record-type="TXT"
                record-host="default._bimi.{{ $domain->domain }}"
                :copy-label="$detail['copyLabel'] ?? 'Copy BIMI record'"
            />
        </div>
    @endif
    @if(!empty($detail['chips']))
        <div class="flex flex-wrap gap-2">
            @foreach($detail['chips'] as $chip)
                <span class="mx-chip">{{ $chip }}</span>
            @endforeach
        </div>
    @endif
@elseif(($detail['type'] ?? '') === 'dkim')
    <div class="mx-tech-detail-sections">
        @if($help)
            <div class="mx-tech-detail-block">
                <h4 class="mx-tech-detail-heading">Why this matters</h4>
                <p class="mx-tech-detail-text">DKIM helps receiving servers verify that messages were not modified.</p>
            </div>
        @endif

        @if(!empty($detail['dnsOnlyNote']))
            <p class="mx-tech-detail-text">{{ $detail['dnsOnlyNote'] }}</p>
        @endif

        @if(!empty($detail['selectors']))
            <div class="mx-tech-detail-block">
                <h4 class="mx-tech-detail-heading">Evidence</h4>
                <x-report.dkim-selectors-table :selectors="$detail['selectors']" />
            </div>
        @endif

        @if(($row['action'] ?? null))
            <div class="mx-tech-detail-block">
                <h4 class="mx-tech-detail-heading">Recommended action</h4>
                <p class="mx-tech-detail-text">{{ $help['fix'] ?? 'Enable DKIM signing in your email provider.' }}</p>
                <a href="#what-to-fix" class="mx-tech-detail-link">View fix instructions</a>
            </div>
        @endif
    </div>
@elseif(($detail['type'] ?? '') === 'mx')
    @if($help)
        <div class="mx-tech-detail-block">
            <h4 class="mx-tech-detail-heading">Why this matters</h4>
            <p class="mx-tech-detail-text">{{ $help['text'] ?? '' }}</p>
        </div>
    @endif
    @if(!empty($detail['rows']))
        <div class="mx-tech-detail-block">
            <h4 class="mx-tech-detail-heading">Evidence</h4>
            <div class="overflow-x-auto">
                <table class="mx-evidence-table">
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Host</th>
                            <th>Status</th>
                            <th>IPv4</th>
                            <th>IPv6</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($detail['rows'] as $mxRows)
                            <tr>
                                <td class="font-medium text-gray-900">{{ $mxRows[0]['value'] ?? '—' }}</td>
                                <td class="font-mono text-[13px] text-gray-900">{{ $mxRows[1]['value'] ?? '—' }}</td>
                                <td class="text-gray-600">{{ $mxRows[2]['value'] ?? '—' }}</td>
                                <td class="font-mono text-[13px] text-gray-700">{{ $mxRows[3]['value'] ?? '—' }}</td>
                                <td class="font-mono text-[13px] text-gray-700">{{ $mxRows[4]['value'] ?? '—' }}</td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </div>
    @endif
@elseif(($detail['type'] ?? '') === 'dmarc_reports')
    @if($help)
        <div class="mx-tech-detail-block">
            <h4 class="mx-tech-detail-heading">Why this matters</h4>
            <p class="mx-tech-detail-text">{{ $help['text'] ?? '' }}</p>
        </div>
    @endif
    @if(!empty($detail['footer']))
        <p class="mx-tech-detail-text text-gray-500">{{ $detail['footer'] }}</p>
    @endif
@elseif(($detail['type'] ?? '') === 'blacklist')
    <p class="mx-tech-detail-text">{{ $detail['hits'] ?? 0 }} listed / {{ $detail['total'] ?? 0 }} checks.</p>
    @if(($enabled['blacklist'] ?? false) && !empty($blacklistRows) && $blacklistRows->count() > 0)
        <div class="mt-2 overflow-x-auto rounded-lg border border-gray-200 bg-white p-3">
            @include('scans.partials._blacklist-table', ['rows' => $blacklistRows])
        </div>
    @endif
@elseif(($detail['type'] ?? '') === 'renewal')
    <p class="mx-tech-detail-text">Domain renewal in {{ $detail['domainDays'] ?? 'unknown' }} days.</p>
@elseif(($detail['type'] ?? '') === 'ssl')
    <p class="mx-tech-detail-text">SSL certificate expires in {{ $detail['sslDays'] ?? 'unknown' }} days.</p>
@endif
