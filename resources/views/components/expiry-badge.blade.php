@props(['domain', 'type' => 'domain'])

@php
    $days = $type === 'domain' ? $domain->getDaysUntilDomainExpiry() : $domain->getDaysUntilSslExpiry();
    $color = $domain->getExpiryBadgeColor($days);
    $label = $type === 'domain' ? 'Domain' : 'SSL';
    $expiryDate = $type === 'domain' ? $domain->domain_expires_at : $domain->ssl_expires_at;
    
    $colorClasses = [
        'red' => 'bg-red-100 text-red-800 border-red-200',
        'amber' => 'bg-amber-100 text-amber-800 border-amber-200',
        'green' => 'bg-green-100 text-green-800 border-green-200',
        'gray' => 'bg-gray-100 text-gray-600 border-gray-200',
    ];
    
    $iconClasses = [
        'red' => 'text-red-600',
        'amber' => 'text-amber-600',
        'green' => 'text-green-600',
        'gray' => 'text-gray-400',
    ];
@endphp

@if($days !== null)
    <div class="inline-flex items-center px-3 py-2 rounded-lg border {{ $colorClasses[$color] }}">
        <i data-lucide="{{ $days < 0 ? 'x-circle' : ($days <= 7 ? 'alert-triangle' : 'clock') }}" 
           class="w-4 h-4 mr-2 {{ $iconClasses[$color] }}"></i>
        <div class="flex flex-col">
            <span class="text-xs font-medium">
                @if($days < 0)
                    {{ $label }} Expired
                @else
                    {{ $label }} renews in {{ $days }} day{{ $days !== 1 ? 's' : '' }}
                @endif
            </span>
            @if($expiryDate)
                <span class="text-xs opacity-75">{{ $expiryDate->format('M j, Y') }}</span>
            @endif
        </div>
    </div>
@else
    <div class="inline-flex items-center px-3 py-2 rounded-lg border {{ $colorClasses['gray'] }}">
        <i data-lucide="help-circle" class="w-4 h-4 mr-2 {{ $iconClasses['gray'] }}"></i>
        <div class="flex flex-col">
            <span class="text-xs font-medium">{{ $label }} expiry unknown</span>
            <a href="{{ route('dashboard.domains.edit', $domain) }}" class="text-xs text-blue-600 hover:underline">
                Set date
            </a>
        </div>
    </div>
@endif
