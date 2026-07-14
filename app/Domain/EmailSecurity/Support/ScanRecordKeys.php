<?php

namespace App\Domain\EmailSecurity\Support;

final class ScanRecordKeys
{
    public const MX = 'MX';
    public const SPF = 'SPF';
    public const DKIM = 'DKIM';
    public const DMARC = 'DMARC';
    public const TLS_RPT = 'TLS-RPT';
    public const MTA_STS = 'MTA-STS';
    public const BIMI = 'BIMI';
}
