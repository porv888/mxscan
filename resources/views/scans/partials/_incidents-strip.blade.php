{{-- Incidents Strip - Priority sorted incidents --}}
@if($incidents->count() > 0)
<div class="mt-6 bg-gradient-to-r from-red-50 to-amber-50 dark:from-red-900/20 dark:to-amber-900/20 border border-red-200 dark:border-red-800 rounded-xl p-4">
    <div class="flex items-center justify-between mb-3">
        <div class="flex items-center">
            <svg class="w-5 h-5 text-red-600 dark:text-red-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
            </svg>
            <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100">Active Incidents ({{ $incidents->count() }})</h3>
        </div>
    </div>
    
    <div class="flex flex-wrap gap-2">
        @foreach($incidents as $incident)
        <div class="inline-flex items-center px-3 py-2 rounded-lg {{ $incident->severity === 'critical' ? 'bg-red-100 dark:bg-red-900/50 border border-red-300 dark:border-red-700' : ($incident->severity === 'warning' ? 'bg-amber-100 dark:bg-amber-900/50 border border-amber-300 dark:border-amber-700' : 'bg-blue-100 dark:bg-blue-900/50 border border-blue-300 dark:border-blue-700') }}">
            {{-- Icon based on type --}}
            @if(str_contains($incident->type, 'blacklist') || str_contains($incident->type, 'rbl'))
                <svg class="w-4 h-4 mr-2 {{ $incident->severity === 'critical' ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400' }}" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" clip-rule="evenodd"></path>
                </svg>
            @elseif(str_contains($incident->type, 'dmarc'))
                <svg class="w-4 h-4 mr-2 {{ $incident->severity === 'critical' ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400' }}" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                </svg>
            @elseif(str_contains($incident->type, 'spf'))
                <svg class="w-4 h-4 mr-2 {{ $incident->severity === 'critical' ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400' }}" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                </svg>
            @elseif(str_contains($incident->type, 'delivery') || str_contains($incident->type, 'tti'))
                <svg class="w-4 h-4 mr-2 {{ $incident->severity === 'critical' ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400' }}" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M2.003 5.884L10 9.882l7.997-3.998A2 2 0 0016 4H4a2 2 0 00-1.997 1.884z"></path>
                    <path d="M18 8.118l-8 4-8-4V14a2 2 0 002 2h12a2 2 0 002-2V8.118z"></path>
                </svg>
            @else
                <svg class="w-4 h-4 mr-2 {{ $incident->severity === 'critical' ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400' }}" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                </svg>
            @endif
            
            <div class="flex-1">
                <div class="text-xs font-medium {{ $incident->severity === 'critical' ? 'text-red-900 dark:text-red-100' : ($incident->severity === 'warning' ? 'text-amber-900 dark:text-amber-100' : 'text-blue-900 dark:text-blue-100') }}">
                    {{ $incident->message }}
                </div>
            </div>
            
            <a href="#fix-pack" class="ml-3 text-xs font-medium {{ $incident->severity === 'critical' ? 'text-red-700 dark:text-red-300 hover:text-red-800 dark:hover:text-red-200' : ($incident->severity === 'warning' ? 'text-amber-700 dark:text-amber-300 hover:text-amber-800 dark:hover:text-amber-200' : 'text-blue-700 dark:text-blue-300 hover:text-blue-800 dark:hover:text-blue-200') }} underline">
                Resolve
            </a>
        </div>
        @endforeach
    </div>
</div>
@endif
