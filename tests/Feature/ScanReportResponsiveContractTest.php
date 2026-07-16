<?php

namespace Tests\Feature;

use Tests\TestCase;

class ScanReportResponsiveContractTest extends TestCase
{
    public function test_report_css_defines_required_mobile_and_desktop_layout_contracts(): void
    {
        $css = file_get_contents(public_path('css/mx-ui.css'));

        $this->assertStringContainsString('@media (max-width: 374px)', $css);
        $this->assertStringContainsString('@media (min-width: 375px)', $css);
        $this->assertStringContainsString('@media (min-width: 1024px)', $css);
        $this->assertStringContainsString('grid-template-columns: repeat(2, minmax(0, 1fr))', $css);
        $this->assertStringContainsString('grid-template-columns: repeat(4, minmax(0, 1fr))', $css);
        $this->assertStringContainsString('.mx-tech-remediation-context', $css);
        $this->assertStringContainsString('min-height: 2.75rem', $css);
        $this->assertStringContainsString('@media (prefers-reduced-motion: reduce)', $css);
        $this->assertStringContainsString('overflow-x: auto', $css);
    }

    public function test_report_components_expose_accessible_interaction_contracts(): void
    {
        $layout = file_get_contents(resource_path('views/layouts/app.blade.php'));
        $checkRow = file_get_contents(resource_path('views/components/report/technical-check-row.blade.php'));
        $recommendation = file_get_contents(resource_path('views/components/report/recommendation-card.blade.php'));
        $copy = file_get_contents(resource_path('views/components/report/copy-button.blade.php'));

        $this->assertStringContainsString('aria-label="Open navigation menu"', $layout);
        $this->assertStringContainsString('id="main-content"', $layout);
        $this->assertStringContainsString(':aria-expanded="expanded.toString()"', $checkRow);
        $this->assertStringContainsString('aria-controls="rec-panel-', $recommendation);
        $this->assertStringContainsString('data-copy-text', $copy);
        $this->assertStringContainsString('aria-live="polite"', $copy);
    }
}
