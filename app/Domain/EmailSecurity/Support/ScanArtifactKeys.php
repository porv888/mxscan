<?php

namespace App\Domain\EmailSecurity\Support;

final class ScanArtifactKeys
{
    public const LEGACY_SPF_RAW = 'legacy_spf_raw';
    public const NATIVE_SPF_RESULT = 'native_spf_result';
    public const NATIVE_DMARC_RESULT = 'native_dmarc_result';
    public const DMARC_DNS_COMPAT = 'dmarc_dns_compat';
    public const NATIVE_DKIM_RESULT = 'native_dkim_result';
    public const DKIM_DNS_COMPAT = 'dkim_dns_compat';
    public const NATIVE_MTA_STS_RESULT = 'native_mta_sts_result';
    public const MTA_STS_DNS_COMPAT = 'mta_sts_dns_compat';
    public const NATIVE_TLS_RPT_RESULT = 'native_tls_rpt_result';
    public const TLS_RPT_DNS_COMPAT = 'tls_rpt_dns_compat';
    public const NATIVE_MX_RESULT = 'native_mx_result';
    public const MX_DNS_COMPAT = 'mx_dns_compat';
    public const NATIVE_BLACKLIST_RESULT = 'native_blacklist_result';
    public const NATIVE_CERTIFICATE_RESULT = 'native_certificate_result';
    public const NATIVE_BIMI_RESULT = 'native_bimi_result';
    public const BIMI_DNS_COMPAT = 'bimi_dns_compat';
}
