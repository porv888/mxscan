<section id="technical-checks"
         class="space-y-5"
         x-data="{
            hidePassing: false,
            setAllChecks(open) {
                this.$el.querySelectorAll('[data-tech-check]').forEach((el) => { el.open = open; });
            }
         }">
    <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
            <h2 class="mx-report-section-title">Technical checks</h2>
            <p class="mx-report-section-subtitle">Detailed DNS, policy and transport-security evidence from the latest scan.</p>
        </div>
        <div class="mx-tech-toolbar">
            <button type="button"
                    class="mx-tech-toolbar-btn"
                    @click="setAllChecks(true)">
                Expand all
            </button>
            <span class="mx-tech-toolbar-sep" aria-hidden="true">·</span>
            <button type="button"
                    class="mx-tech-toolbar-btn"
                    @click="setAllChecks(false)">
                Collapse all
            </button>
            <label class="mx-tech-toolbar-toggle">
                <input type="checkbox"
                       class="mx-tech-toolbar-checkbox"
                       x-model="hidePassing">
                <span>Hide passing checks</span>
            </label>
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
                    <div x-show="!hidePassing || '{{ $row['badgeVariant'] ?? 'neutral' }}' !== 'success'" x-cloak>
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
