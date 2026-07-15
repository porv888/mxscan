<?php

namespace Tests\Unit;

use Tests\TestCase;

class DeployPreflightTest extends TestCase
{
    public function test_preflight_passes_when_native_spf_is_mandatory(): void
    {
        $this->artisan('deploy:preflight')
            ->assertSuccessful()
            ->expectsOutput('Deploy preflight passed: native SPF pipeline is mandatory and legacy fallback is absent.');
    }
}
