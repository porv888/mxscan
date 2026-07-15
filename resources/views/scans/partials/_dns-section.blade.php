{{-- DNS & technical details — summary grid + grouped detail panels --}}
@php
    use App\View\Presenters\DnsSectionPresenter;

    $presenter = new DnsSectionPresenter(
        records: $records,
        statusCards: $statusCards ?? [],
        dmarcStatus: $dmarcStatus ?? null,
        spfLookupCount: $spfLookupCount ?? null,
        domain: $domain,
        dmarcPolicy: $dmarcPolicy ?? null,
        dmarcAligned: $dmarcAligned ?? null,
        dmarcAlignmentVerification: $dmarcAlignmentVerification ?? null,
        dkimInfo: $dkimInfo ?? null,
        spfMax: $spfMax ?? 10,
        mxInfo: $mxInfo ?? null,
        bimiInfo: $bimiInfo ?? null,
        scan: $scan ?? null,
    );

    $summaryTiles = $presenter->summaryTiles();
    $detailGroups = $presenter->detailGroups();
    $recordHelp = $presenter->recordHelp();
    $sectionOpenDefault = $presenter->sectionOpenByDefault();
@endphp

<section id="dns-security"
         class="rounded-xl border border-gray-200 bg-white p-6 dark:border-gray-700 dark:bg-gray-800"
         x-data="{ sectionOpen: {{ $sectionOpenDefault ? 'true' : 'false' }} }">
    <x-dns.section-header />

    @if($presenter->allGreen())
        <p x-show="!sectionOpen" x-cloak class="mt-3 text-sm text-green-700 dark:text-green-300">All DNS checks configured.</p>
    @endif

    <div id="dns-section-body" x-show="sectionOpen" x-collapse class="mt-5 space-y-6">
        {{-- Level 2: Summary grid --}}
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
            @foreach($summaryTiles as $tile)
                <x-dns.summary-tile
                    :label="$tile['label']"
                    :badge-variant="$tile['badgeVariant']"
                    :badge-label="$tile['badgeLabel']"
                    :summary="$tile['summary']"
                    :severity="$tile['severity']"
                    :accent="$tile['accent']"
                    :primary-action="$tile['primaryAction'] ?? null"
                    :detail-id="$tile['detailId']"
                />
            @endforeach
        </div>

        {{-- Level 3: Grouped detail panels --}}
        <div class="space-y-5">
            @foreach($detailGroups as $group)
                <div>
                    <h4 class="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">{{ $group['label'] }}</h4>
                    <div class="space-y-2">
                        @foreach($group['items'] as $detail)
                            @php
                                $help = $recordHelp[$detail['helpKey']] ?? null;
                            @endphp
                            <x-dns.detail-card
                                :id="$detail['id']"
                                :label="$detail['label']"
                                :badge-variant="$detail['badgeVariant']"
                                :badge-label="$detail['badgeLabel']"
                                :explanation="$detail['explanation']"
                                :severity="$detail['severity']"
                                :primary-action="$detail['primaryAction'] ?? null"
                                :open="$detail['open'] ?? false"
                                :help="$help"
                            >
                                @switch($detail['type'])
                                    @case('code')
                                        @if(!empty($detail['value']))
                                            <x-dns.code-value :value="$detail['value']" :copy-label="$detail['copyLabel'] ?? 'Copy record'" />
                                        @endif

                                        @if(!empty($detail['chips']))
                                            <div class="mt-3 flex flex-wrap gap-2">
                                                @foreach($detail['chips'] as $chip)
                                                    <span class="inline-flex rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-700 dark:bg-gray-700 dark:text-gray-300">{{ $chip }}</span>
                                                @endforeach
                                            </div>
                                        @endif

                                        @if(isset($detail['lookupCount']))
                                            <p class="mt-3 text-xs text-gray-600 dark:text-gray-400">
                                                Lookup count: {{ $detail['lookupCount'] }}/{{ $detail['lookupMax'] ?? 10 }}
                                                @if($detail['lookupCount'] >= 7)
                                                    <x-help-tooltip
                                                        :title="$recordHelp['spf_lookup']['title']"
                                                        :text="$recordHelp['spf_lookup']['text']"
                                                        :impact="$recordHelp['spf_lookup']['impact']"
                                                        :fix="$recordHelp['spf_lookup']['fix']"
                                                    />
                                                @endif
                                            </p>
                                            @if(!empty($detail['showOptimize']))
                                                <a href="{{ $presenter->spfOptimizeUrl() }}" class="mt-2 inline-flex text-xs font-medium text-blue-700 hover:underline dark:text-blue-300">Optimize SPF lookups</a>
                                            @endif
                                        @endif
                                        @break

                                    @case('dkim')
                                        <p class="text-xs leading-5 text-gray-600 dark:text-gray-400">{{ $detail['dnsOnlyNote'] }}</p>
                                        @if(!empty($detail['selectors']))
                                            <ul class="mt-3 space-y-3">
                                                @foreach($detail['selectors'] as $selector)
                                                    <li class="rounded-lg border border-gray-200 p-3 dark:border-gray-700">
                                                        <div class="mb-2 flex flex-wrap items-center gap-2">
                                                            <span class="inline-flex rounded bg-blue-100 px-1.5 py-0.5 text-xs font-medium text-blue-800 dark:bg-blue-900 dark:text-blue-200">{{ $selector['selector'] }}</span>
                                                            <span class="text-xs text-gray-500 dark:text-gray-400">{{ $selector['host'] }}</span>
                                                        </div>
                                                        <div x-data="{ expanded: false }">
                                                            <code class="block break-all font-mono text-xs text-gray-900 dark:text-gray-100" x-show="!expanded">{{ $selector['preview'] }}</code>
                                                            @if(strlen($selector['record']) > 80)
                                                                <code class="block break-all font-mono text-xs text-gray-900 dark:text-gray-100" x-show="expanded" x-cloak>{{ $selector['record'] }}</code>
                                                                <button type="button" class="mt-1 text-xs font-medium text-blue-700 hover:underline dark:text-blue-300" @click="expanded = !expanded" x-text="expanded ? 'Show less' : 'Show full value'"></button>
                                                            @endif
                                                            <button type="button"
                                                                    onclick="copyToClipboard('{{ e(addslashes($selector['record'])) }}', this)"
                                                                    class="mx-btn mx-btn-ghost mx-btn-sm mt-2"
                                                                    aria-label="Copy DKIM record for {{ $selector['selector'] }}">
                                                                Copy
                                                            </button>
                                                        </div>
                                                    </li>
                                                @endforeach
                                            </ul>
                                        @else
                                            <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">Checked {{ $detail['checkedCount'] ?? 0 }} common selectors.</p>
                                        @endif
                                        @break

                                    @case('mx')
                                        @if(!empty($detail['rows']))
                                            <x-dns.record-kv-list :entries="$detail['rows']" />
                                        @endif
                                        @break

                                    @case('dmarc_reports')
                                        <a href="{{ $detail['visibilityUrl'] }}" class="text-xs font-medium text-blue-700 hover:underline dark:text-blue-300">Open DMARC visibility</a>
                                        @if(!empty($detail['footer']))
                                            <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">{{ $detail['footer'] }}</p>
                                        @endif
                                        @break
                                @endswitch
                            </x-dns.detail-card>
                        @endforeach
                    </div>
                </div>
            @endforeach
        </div>
    </div>
</section>
