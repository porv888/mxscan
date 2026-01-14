{{ $typeLabel }} Expiry Notice - MXScan
========================================

Notice: Your {{ strtolower($typeLabel) }} for {{ $domain->domain }} will expire in {{ $days }} day{{ $days !== 1 ? 's' : '' }}.

Details:
- Domain: {{ $domain->domain }}
- {{ $typeLabel }}: Expires {{ $expiryDate->format('F j, Y') }}
- Days Remaining: {{ $days }}

View domain status: {{ route('domains.hub', $domain) }}

---
You're receiving this because expiry monitoring is enabled for this domain.

MXScan - Email Security Monitoring
{{ route('dashboard') }}
