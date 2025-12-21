@props(['label', 'value', 'action' => null])

<div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
    <div class="flex-1 min-w-0">
        <div class="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">{{ $label }}</div>
        <code class="text-sm text-gray-900 dark:text-gray-100 break-all">{{ $value }}</code>
    </div>
    <div class="flex items-center gap-2 ml-4">
        @if($action)
            <a href="{{ $action }}" target="_blank" class="px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 rounded-md hover:bg-blue-100 dark:bg-blue-900 dark:text-blue-200 dark:hover:bg-blue-800 transition-colors">
                Learn More
            </a>
        @endif
        <button 
            onclick="copyToClipboard('{{ addslashes($value) }}', this)"
            class="px-3 py-1.5 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 dark:bg-gray-700 dark:text-gray-200 dark:border-gray-600 dark:hover:bg-gray-600 transition-colors">
            Copy
        </button>
    </div>
</div>
