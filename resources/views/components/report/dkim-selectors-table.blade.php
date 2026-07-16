@props([
    'selectors' => [],
])

<div class="mx-dkim-selectors" x-data="{ expandedSelector: null }">
    <table class="mx-dkim-table mx-dkim-table--desktop">
        <thead>
            <tr>
                <th scope="col">Selector</th>
                <th scope="col">Host</th>
                <th scope="col">Key</th>
                <th scope="col">Status</th>
                <th scope="col"><span class="sr-only">Action</span></th>
            </tr>
        </thead>
        <tbody>
            @foreach($selectors as $selector)
                @php
                    $selectorId = $selector['selector'] ?? 'unknown';
                @endphp
                <tr class="mx-dkim-table-row">
                    <td class="font-medium text-gray-900">{{ $selectorId }}</td>
                    <td class="font-mono text-[12px] text-gray-700">{{ $selector['host'] ?? '—' }}</td>
                    <td class="text-gray-600">{{ $selector['keyLabel'] ?? '—' }}</td>
                    <td class="text-gray-600">{{ $selector['statusLabel'] ?? 'Published' }}</td>
                    <td class="text-right">
                        <button type="button"
                                class="mx-dkim-view-btn"
                                @click="expandedSelector = expandedSelector === @js($selectorId) ? null : @js($selectorId)">
                            View
                        </button>
                    </td>
                </tr>
                <tr class="mx-dkim-detail-row" x-show="expandedSelector === @js($selectorId)" x-cloak>
                    <td colspan="5">
                        <x-report.dkim-selector-record :selector="$selector" />
                    </td>
                </tr>
            @endforeach
        </tbody>
    </table>

    <div class="mx-dkim-table--mobile">
        @foreach($selectors as $selector)
            @php
                $selectorId = $selector['selector'] ?? 'unknown';
            @endphp
            <div class="mx-dkim-mobile-row">
                <div class="mx-dkim-mobile-row-main">
                    <div class="min-w-0">
                        <div class="font-medium text-gray-900">{{ $selectorId }}</div>
                        <div class="truncate font-mono text-[12px] text-gray-600">{{ $selector['host'] ?? '—' }}</div>
                    </div>
                    <div class="text-right text-[12px] text-gray-600">
                        <div>{{ $selector['keyLabel'] ?? '—' }}</div>
                        <div>{{ $selector['statusLabel'] ?? 'Published' }}</div>
                    </div>
                    <button type="button"
                            class="mx-dkim-view-btn"
                            @click="expandedSelector = expandedSelector === @js($selectorId) ? null : @js($selectorId)">
                        View
                    </button>
                </div>
                <div x-show="expandedSelector === @js($selectorId)" x-cloak>
                    <x-report.dkim-selector-record :selector="$selector" />
                </div>
            </div>
        @endforeach
    </div>
</div>
