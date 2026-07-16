@php
    $servers = $row['detail']['detectedMailServers'] ?? [];
    $providers = $technicalRemediation['sender_providers'] ?? [];
    $initialSpf = $technicalRemediation['spf'] ?? [];
@endphp

<div class="mx-spf-builder" data-spf-remediation-builder>
    <div class="mx-spf-step">
        <h5>Step 1 — Confirm who sends email</h5>
        <p>Inbound MX records do not prove which servers send outgoing email. Confirm each detected sender before publishing SPF.</p>
    </div>

    @if($servers !== [])
        <h5>Detected infrastructure — confirmation required</h5>
    @endif

    @forelse($servers as $server)
        <article class="mx-detected-sender" data-sender-confidence="pending">
            <div>
                <span class="mx-confidence-badge">Likely · confirmation required</span>
                <h6>Detected mail server</h6>
                <strong>{{ $server['hostname'] }}</strong>
                @foreach($server['ipv4'] as $ip)
                    <code>IPv4: {{ $ip }}</code>
                @endforeach
                @foreach($server['ipv6'] as $ip)
                    <code>IPv6: {{ $ip }}</code>
                @endforeach
            </div>
            <div>
                <p>Does this server also send outgoing email for this domain?</p>
                <div class="mx-tech-action-row">
                    <button type="button" class="mx-btn mx-btn-primary" @click="setServer({{ \Illuminate\Support\Js::from($server) }}, 'confirmed')">Yes, authorize it</button>
                    <button type="button" class="mx-btn mx-btn-secondary" @click="setServer({{ \Illuminate\Support\Js::from($server) }}, 'rejected')">No</button>
                    <button type="button" class="mx-btn mx-btn-ghost" @click="setServer({{ \Illuminate\Support\Js::from($server) }}, 'pending')">Not sure</button>
                </div>
            </div>
        </article>
    @empty
        <div class="mx-tech-empty-state">
            <strong>No sending infrastructure has been identified.</strong>
            <p>Select a provider or add your own server IP to build SPF.</p>
        </div>
    @endforelse

    <div class="mx-spf-provider-picker">
        <h5>Add sending services</h5>
        <div class="mx-spf-provider-grid">
            @foreach($providers as $key => $provider)
                <label>
                    <input type="checkbox"
                           :checked="providerSelected('{{ $key }}')"
                           @change="toggleProvider('{{ $key }}', $event.target.checked)">
                    <span>{{ $provider['name'] }}</span>
                </label>
            @endforeach
        </div>
        <div class="mx-custom-sender-input">
            <input type="text" x-model="customIp" placeholder="Own server IPv4 or IPv6 address" aria-label="Own server IP address">
            <button type="button" class="mx-btn mx-btn-secondary" @click="addCustomSender()">Add server</button>
        </div>
    </div>

    <div class="mx-spf-generated-record">
        <div class="mx-spf-record-heading">
            <div>
                <h5 x-text="spf.state || 'Cannot generate yet'">{{ $initialSpf['state'] ?? 'Cannot generate yet' }}</h5>
                <p x-text="spf.record ? (spf.policy === '-all' ? 'Validated SPF record' : 'Suggested starting SPF record') : 'Build your SPF record by confirming a sender.'"></p>
            </div>
            <strong x-text="spf.record ? (spf.score + '/20') : 'Up to +20 points'">{{ !empty($initialSpf['record']) ? (($initialSpf['score'] ?? 0) . '/20') : 'Up to +20 points' }}</strong>
        </div>

        <template x-if="spf.record">
            <div class="mx-dns-solution-record">
                <h5>Suggested SPF record</h5>
                <dl class="mx-dns-solution-fields">
                    <div><dt>Type</dt><dd>TXT</dd></div>
                    <div><dt>Host</dt><dd><code>@</code></dd></div>
                    <div><dt>TTL</dt><dd>Auto</dd></div>
                    <div class="mx-dns-solution-value"><dt>Value</dt><dd><code x-text="spf.record">{{ $initialSpf['record'] ?? '' }}</code></dd></div>
                </dl>
                <div class="mx-tech-action-row">
                    <button type="button" class="mx-btn mx-btn-secondary" @click="copy('@')">Copy host</button>
                    <button type="button" class="mx-btn mx-btn-primary" @click="copy(spf.record)">Copy value</button>
                    <button type="button" class="mx-btn mx-btn-secondary" @click="copy('TXT @ ' + spf.record)">Copy full record</button>
                </div>
            </div>
        </template>

        <div class="mx-spf-policy-options">
            <label>
                <input type="radio" x-model="policy" value="~all" @change="preview()">
                <span><strong>Keep soft fail: ~all</strong> — 15/20</span>
            </label>
            <label :class="{ 'opacity-50': !spf.all_senders_resolved }">
                <input type="radio" x-model="policy" value="-all" :disabled="!spf.all_senders_resolved" @change="preview()">
                <span><strong>Enforce hard fail: -all</strong> — 20/20</span>
            </label>
            <p x-show="!spf.all_senders_resolved">Hard fail becomes available after every detected sender is confirmed or rejected.</p>
        </div>

        <div class="mx-spf-validation" :class="spf.errors && spf.errors.length ? 'mx-spf-validation--warning' : 'mx-spf-validation--ready'">
            <strong x-text="spf.errors && spf.errors.length ? 'Needs attention' : (spf.record ? spf.state : 'Cannot generate yet')"></strong>
            <ul>
                <li x-show="spf.record">Syntax valid</li>
                <li x-show="spf.record"><span x-text="spf.mechanisms ? spf.mechanisms.length : 0"></span> authorized mechanisms</li>
                <li x-show="spf.record"><span x-text="spf.lookup_count || 0"></span> DNS lookups</li>
                <template x-for="error in (spf.errors || [])" :key="error.code"><li x-text="error.message"></li></template>
                <template x-for="warning in (spf.warnings || [])" :key="warning.code"><li x-text="warning.message"></li></template>
            </ul>
        </div>

        <p class="mx-tech-supporting-note">This record authorizes only the sending infrastructure you confirmed. Add every external service that sends email using this domain before publishing it.</p>
        <p class="mx-tech-score-gain">Estimated score after publishing: <strong x-text="spf.record ? (spf.score + '/20') : 'Up to 20/20'">{{ !empty($initialSpf['record']) ? (($initialSpf['score'] ?? 0) . '/20') : 'Up to 20/20' }}</strong></p>
    </div>

    <x-report.dns-provider-instructions
        :providers="$technicalRemediation['dns_providers'] ?? []"
        :selected="$technicalRemediation['dns_provider'] ?? null"
    />

    <p class="mx-form-error" x-show="saveError" x-text="saveError" x-cloak></p>
    <div class="mx-tech-action-row">
        <button type="button" class="mx-btn mx-btn-secondary" @click="save()" :disabled="saving">
            <span x-text="saving ? 'Saving…' : 'Save sender choices'">Save sender choices</span>
        </button>
        <x-report.rescan-button />
    </div>
</div>
