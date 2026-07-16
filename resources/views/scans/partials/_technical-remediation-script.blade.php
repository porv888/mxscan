@php
    $allRows = collect($techGroups ?? [])->flatMap(fn ($group) => $group['items'] ?? []);
    $spfRow = $allRows->firstWhere('key', 'spf') ?? [];
    $detectedServers = $spfRow['detail']['detectedMailServers'] ?? [];
    $initialSenders = collect($technicalRemediation['senders'] ?? []);

    foreach ($detectedServers as $server) {
        foreach (array_merge(
            array_map(fn ($value) => ['mechanism' => 'ip4', 'value' => $value], $server['ipv4'] ?? []),
            array_map(fn ($value) => ['mechanism' => 'ip6', 'value' => $value], $server['ipv6'] ?? []),
        ) as $address) {
            if (!$initialSenders->contains(fn ($row) => ($row['mechanism'] ?? '') === $address['mechanism'] && ($row['value'] ?? '') === $address['value'])) {
                $initialSenders->push([
                    'sender_type' => 'own_server',
                    'provider' => null,
                    'mechanism' => $address['mechanism'],
                    'value' => $address['value'],
                    'source' => 'detected',
                    'confidence' => 'likely',
                    'confirmation_status' => 'pending',
                    'is_active' => true,
                ]);
            }
        }
    }
@endphp

<script>
window.technicalChecksRemediation = function () {
    return {
        hidePassing: false,
        busy: false,
        saving: false,
        saveError: '',
        copyStatus: '',
        spfStep: 1,
        showProviderPicker: false,
        providerSearch: '',
        selectedProvider: '',
        policy: '~all',
        dnsProvider: {{ \Illuminate\Support\Js::from($technicalRemediation['dns_provider'] ?? '') }},
        senders: {{ \Illuminate\Support\Js::from($initialSenders->values()->all()) }},
        providers: {{ \Illuminate\Support\Js::from($technicalRemediation['sender_providers'] ?? []) }},
        spf: {{ \Illuminate\Support\Js::from($technicalRemediation['spf'] ?? []) }},
        customIp: '',
        customInclude: '',
        previewUrl: {{ \Illuminate\Support\Js::from(route('domains.remediation.spf.preview', $domain)) }},
        saveUrl: {{ \Illuminate\Support\Js::from(route('domains.remediation.spf.save', $domain)) }},
        csrf: {{ \Illuminate\Support\Js::from(csrf_token()) }},

        setAllChecks(open) {
            this.$el.querySelectorAll('[data-tech-check]').forEach((el) => { el.open = open; });
        },
        serverStatus(server) {
            const values = [...(server.ipv4 || []), ...(server.ipv6 || [])];
            const rows = this.senders.filter((sender) => values.includes(sender.value));
            if (rows.length && rows.every((sender) => sender.confirmation_status === 'confirmed')) return 'confirmed';
            if (rows.length && rows.every((sender) => sender.confirmation_status === 'rejected')) return 'rejected';
            return 'pending';
        },
        setServer(server, status) {
            const values = [
                ...(server.ipv4 || []).map((value) => ({ mechanism: 'ip4', value })),
                ...(server.ipv6 || []).map((value) => ({ mechanism: 'ip6', value })),
            ];
            values.forEach((address) => {
                let sender = this.senders.find((item) => item.mechanism === address.mechanism && item.value === address.value);
                if (!sender) {
                    sender = { sender_type: 'own_server', provider: null, source: 'detected', confidence: 'likely', is_active: true, ...address };
                    this.senders.push(sender);
                }
                sender.confirmation_status = status;
                sender.confidence = status === 'confirmed' ? 'confirmed' : 'likely';
            });
            this.preview();
        },
        providerSelected(key) {
            return this.senders.some((sender) => sender.provider === key && sender.confirmation_status === 'confirmed' && sender.is_active !== false);
        },
        toggleProvider(key, selected) {
            const definition = this.providers[key];
            let sender = this.senders.find((item) => item.provider === key && item.mechanism === 'include');
            if (selected) {
                if (!sender) {
                    sender = {
                        sender_type: 'provider',
                        provider: key,
                        mechanism: 'include',
                        value: definition.include,
                        source: 'user_added',
                        confidence: 'confirmed',
                        confirmation_status: 'confirmed',
                        is_active: true,
                    };
                    this.senders.push(sender);
                } else {
                    sender.confirmation_status = 'confirmed';
                    sender.confidence = 'confirmed';
                    sender.is_active = true;
                }
            } else if (sender) {
                sender.confirmation_status = sender.source === 'detected' ? 'rejected' : 'pending';
                sender.is_active = sender.source === 'detected';
            }
            this.preview();
        },
        addCustomSender() {
            const value = this.customIp.trim();
            if (!value) return;
            const mechanism = value.includes(':') ? 'ip6' : 'ip4';
            if (!this.senders.some((sender) => sender.mechanism === mechanism && sender.value === value)) {
                this.senders.push({
                    sender_type: 'own_server',
                    provider: null,
                    mechanism,
                    value,
                    source: 'user_added',
                    confidence: 'confirmed',
                    confirmation_status: 'confirmed',
                    is_active: true,
                });
            }
            this.customIp = '';
            this.preview();
        },
        addCustomInclude() {
            const value = this.customInclude.trim().toLowerCase();
            if (!value) return;
            if (!this.senders.some((sender) => sender.mechanism === 'include' && sender.value === value)) {
                this.senders.push({
                    sender_type: 'provider',
                    provider: 'custom',
                    mechanism: 'include',
                    value,
                    source: 'user_added',
                    confidence: 'confirmed',
                    confirmation_status: 'confirmed',
                    is_active: true,
                });
            }
            this.customInclude = '';
            this.preview();
        },
        addSelectedProvider() {
            if (!this.selectedProvider) return;
            this.toggleProvider(this.selectedProvider, true);
            this.selectedProvider = '';
        },
        payload() {
            return { senders: this.senders, policy: this.policy, dns_provider: this.dnsProvider || null };
        },
        async request(url) {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-TOKEN': this.csrf },
                body: JSON.stringify(this.payload()),
            });
            if (!response.ok) {
                const data = await response.json().catch(() => ({}));
                throw new Error(data.message || data.error || 'Unable to save remediation settings.');
            }
            return response.json();
        },
        async preview() {
            this.saveError = '';
            try {
                const data = await this.request(this.previewUrl);
                this.spf = data.spf;
                if (this.spf.policy !== this.policy) this.policy = this.spf.policy;
            } catch (error) {
                this.saveError = error.message;
            }
        },
        async save() {
            this.saving = true;
            this.saveError = '';
            try {
                const data = await this.request(this.saveUrl);
                this.spf = data.spf;
                return true;
            } catch (error) {
                this.saveError = error.message;
                return false;
            } finally {
                this.saving = false;
            }
        },
        async rescan() {
            if (this.busy) return;
            this.busy = true;
            if (await this.save()) {
                this.$refs.rescanForm.submit();
                return;
            }
            this.busy = false;
        },
        copy(value) {
            navigator.clipboard.writeText(value || '').then(() => {
                this.copyStatus = 'Copied';
                setTimeout(() => { this.copyStatus = ''; }, 1500);
            }).catch(() => {
                this.copyStatus = 'Copy failed';
            });
        },
    };
};
</script>

<form x-ref="rescanForm" method="POST" action="{{ route('domains.scan.now', $domain) }}" class="hidden">
    @csrf
    <input type="hidden" name="mode" value="full">
</form>
