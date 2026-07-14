@props([
    'entries' => [],
])

<div {{ $attributes->merge(['class' => 'min-w-0 overflow-x-auto']) }}>
    @foreach($entries as $entry)
        <div class="mb-3 last:mb-0 rounded-lg border border-gray-200 dark:border-gray-700">
            <dl class="divide-y divide-gray-100 dark:divide-gray-700 text-sm">
                @foreach($entry as $row)
                    <div class="flex flex-col gap-0.5 px-3 py-2 sm:flex-row sm:items-start sm:justify-between">
                        <dt class="shrink-0 text-xs font-medium text-gray-500 dark:text-gray-400">{{ $row['label'] }}</dt>
                        <dd class="min-w-0 font-mono text-xs text-gray-900 break-all dark:text-gray-100">{{ $row['value'] }}</dd>
                    </div>
                @endforeach
            </dl>
        </div>
    @endforeach
</div>
