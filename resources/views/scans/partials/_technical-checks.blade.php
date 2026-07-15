<section id="technical-checks"
         class="space-y-5"
         x-data="{
            showResolved: true,
            setAllChecks(open) {
                this.$el.querySelectorAll('[data-tech-check]').forEach((el) => { el.open = open; });
            }
         }">
    <div class="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
            <h2 class="mx-report-section-title">Technical checks</h2>
            <p class="mx-report-section-subtitle">Detailed DNS, policy and transport-security evidence from the latest scan.</p>
        </div>
        <div class="flex flex-wrap items-center gap-2">
            <button type="button"
                    class="min-h-[44px] rounded-lg border border-gray-200 bg-white px-3 text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                    @click="setAllChecks(true)">
                Expand all
            </button>
            <button type="button"
                    class="min-h-[44px] rounded-lg border border-gray-200 bg-white px-3 text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                    @click="setAllChecks(false)">
                Collapse all
            </button>
            <button type="button"
                    class="min-h-[44px] rounded-lg border border-gray-200 bg-white px-3 text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                    @click="showResolved = !showResolved"
                    x-text="showResolved ? 'Hide resolved checks' : 'Show resolved checks'">
            </button>
        </div>
    </div>

    <div class="space-y-5 lg:space-y-6">
        @foreach($techGroups as $group)
            @php $summary = $group['summary'] ?? []; @endphp
            <x-report.technical-category-card
                :label="$group['label']"
                :icon="$group['icon'] ?? 'folder'"
                :summary="$summary['summary'] ?? null"
                :status-variant="$summary['statusVariant'] ?? null"
                :status-label="$summary['statusLabel'] ?? null"
            >
                @foreach($group['items'] as $row)
                    <div x-show="showResolved || '{{ $row['badgeVariant'] ?? 'neutral' }}' !== 'success'" x-cloak>
                        <x-report.technical-check-row
                            :id="$row['id']"
                            :icon="$row['icon']"
                            :label="$row['label']"
                            :badge-variant="$row['badgeVariant']"
                            :badge-label="$row['badgeLabel']"
                            :result="$row['result']"
                            :metadata="$row['metadata'] ?? null"
                            :action="$row['action'] ?? null"
                            :open="$row['open'] ?? false"
                        >
                            @include('scans.partials._technical-check-detail', [
                                'row' => $row,
                                'domain' => $domain,
                                'blacklistRows' => $blacklistRows,
                                'enabled' => $enabled,
                            ])
                        </x-report.technical-check-row>
                    </div>
                @endforeach
            </x-report.technical-category-card>
        @endforeach
    </div>
</section>
