<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\File;
use Tests\TestCase;

class BrandingMxscanTest extends TestCase
{
    public function test_customer_layout_contains_mxscan_not_emailsec(): void
    {
        $html = view('layouts.app')->render();
        $this->assertStringContainsString('MXScan', $html);
        $this->assertStringNotContainsString('EmailSec', $html);
        $this->assertStringContainsString('- MXScan</title>', $html);
    }

    public function test_admin_layout_contains_mxscan_admin_not_emailsec(): void
    {
        $src = File::get(resource_path('views/admin/layouts/app.blade.php'));
        $this->assertStringContainsString('MXScan Admin', $src);
        $this->assertStringNotContainsString('EmailSec', $src);
    }

    public function test_blacklist_alert_mentions_mxscan(): void
    {
        $src = File::get(app_path('Notifications/BlacklistAlert.php'));
        $this->assertStringContainsString('MXScan monitoring system', $src);
        $this->assertStringNotContainsString('EmailSec monitoring system', $src);
    }

    public function test_env_example_and_config_fallback_use_mxscan(): void
    {
        $example = File::get(base_path('.env.example'));
        $this->assertMatchesRegularExpression('/^APP_NAME=MXScan$/m', $example);
        $appConfig = File::get(config_path('app.php'));
        $this->assertStringContainsString("env('APP_NAME', 'MXScan')", $appConfig);
    }
}
