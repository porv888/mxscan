<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ $typeLabel }} Expiry Reminder</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 20px;
            text-align: center;
            border-radius: 8px 8px 0 0;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
        }
        .content {
            background: #fff;
            padding: 30px 20px;
            border: 1px solid #e5e7eb;
            border-top: none;
        }
        .alert-box {
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
        }
        .alert-critical {
            background: #fef2f2;
            border-left: 4px solid #dc2626;
            color: #991b1b;
        }
        .alert-high {
            background: #fefce8;
            border-left: 4px solid #eab308;
            color: #854d0e;
        }
        .alert-medium {
            background: #eff6ff;
            border-left: 4px solid #3b82f6;
            color: #1e40af;
        }
        .info-table {
            width: 100%;
            margin: 20px 0;
            border-collapse: collapse;
        }
        .info-table td {
            padding: 10px;
            border-bottom: 1px solid #e5e7eb;
        }
        .info-table td:first-child {
            font-weight: 600;
            width: 40%;
        }
        .button {
            display: inline-block;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            margin: 20px 0;
        }
        .button:hover {
            background: #5568d3;
        }
        .recommendations {
            background: #f9fafb;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
        }
        .recommendations h3 {
            margin-top: 0;
            color: #374151;
        }
        .recommendations ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin: 8px 0;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #6b7280;
            font-size: 14px;
            border-top: 1px solid #e5e7eb;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔔 {{ $typeLabel }} Expiry Alert</h1>
    </div>

    <div class="content">
        <div class="alert-box alert-{{ $urgency }}">
            <strong>⚠️ Action Required:</strong> Your {{ strtolower($typeLabel) }} for <strong>{{ $domain->domain }}</strong> will expire in <strong>{{ $days }} day{{ $days !== 1 ? 's' : '' }}</strong>.
        </div>

        <table class="info-table">
            <tr>
                <td>Domain</td>
                <td><strong>{{ $domain->domain }}</strong></td>
            </tr>
            <tr>
                <td>{{ $typeLabel }}</td>
                <td><strong>Expires {{ $expiryDate->format('F j, Y') }}</strong></td>
            </tr>
            <tr>
                <td>Days Remaining</td>
                <td><strong>{{ $days }} day{{ $days !== 1 ? 's' : '' }}</strong></td>
            </tr>
            <tr>
                <td>Urgency Level</td>
                <td>
                    @if($urgency === 'critical')
                        <span style="color: #dc2626;">🔴 Critical</span>
                    @elseif($urgency === 'high')
                        <span style="color: #eab308;">🟡 High</span>
                    @else
                        <span style="color: #3b82f6;">🔵 Medium</span>
                    @endif
                </td>
            </tr>
        </table>

        <div class="recommendations">
            <h3>📋 Recommended Actions</h3>
            @if($type === 'domain')
                <ul>
                    <li><strong>Renew your domain registration</strong> with your registrar immediately</li>
                    <li>Enable auto-renewal to prevent future expiration</li>
                    <li>Verify your contact information is up to date</li>
                    <li>Check for renewal notices in your registrar account</li>
                </ul>
                <p style="margin-top: 15px; color: #6b7280;">
                    <strong>Note:</strong> Domain expiration can result in website downtime, email service disruption, and potential loss of your domain name.
                </p>
            @else
                <ul>
                    <li><strong>Renew or replace your SSL certificate</strong> before expiration</li>
                    <li>Consider using Let's Encrypt for free auto-renewing certificates</li>
                    <li>Update your certificate with your hosting provider or CDN</li>
                    <li>Test the new certificate after installation</li>
                </ul>
                <p style="margin-top: 15px; color: #6b7280;">
                    <strong>Note:</strong> An expired SSL certificate will cause browser warnings and may prevent users from accessing your site.
                </p>
            @endif
        </div>

        <center>
            <a href="{{ route('domains.hub', $domain) }}" class="button">
                View Domain Details →
            </a>
        </center>

        <p style="margin-top: 30px; color: #6b7280; font-size: 14px;">
            This is an automated reminder from MXScan. You're receiving this because you have expiry monitoring enabled for this domain.
        </p>
    </div>

    <div class="footer">
        <p>
            <strong>MXScan</strong> - Email Security Monitoring<br>
            <a href="{{ route('dashboard') }}" style="color: #667eea;">Dashboard</a> | 
            <a href="{{ route('settings.notifications') }}" style="color: #667eea;">Notification Settings</a>
        </p>
        <p style="font-size: 12px; color: #9ca3af; margin-top: 10px;">
            © {{ date('Y') }} MXScan. All rights reserved.
        </p>
    </div>
</body>
</html>
