@props([
    'providers' => [],
    'selected' => null,
])

<div class="mx-dns-provider-instructions">
    <label>
        <span>Choose DNS provider</span>
        <select x-model="dnsProvider" @change="preview()">
            <option value="">Select provider</option>
            @foreach($providers as $key => $provider)
                <option value="{{ $key }}" @selected($selected === $key)>{{ $provider['name'] }}</option>
            @endforeach
        </select>
    </label>
    @foreach($providers as $key => $provider)
        <div x-show="dnsProvider === '{{ $key }}'" x-cloak class="mx-dns-provider-steps">
            <strong>{{ $provider['name'] }} instructions</strong>
            <ol>
                @foreach($provider['steps'] as $step)
                    <li>{{ $step }}</li>
                @endforeach
                <li>Return to MXScan and click Re-scan domain.</li>
            </ol>
        </div>
    @endforeach
</div>
