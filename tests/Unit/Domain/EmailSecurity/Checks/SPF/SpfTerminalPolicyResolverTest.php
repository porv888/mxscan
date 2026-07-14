<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicyResolver;
use Tests\TestCase;

class SpfTerminalPolicyResolverTest extends TestCase
{
    private SpfTerminalPolicyResolver $resolver;

    protected function setUp(): void
    {
        parent::setUp();
        $this->resolver = new SpfTerminalPolicyResolver();
    }

    public function test_hard_fail_mapping(): void
    {
        $this->assertSame(
            SpfTerminalPolicy::HARD_FAIL,
            $this->resolver->resolve(['qualifier' => '-', 'mechanism' => 'all'], true)
        );
    }

    public function test_soft_fail_mapping(): void
    {
        $this->assertSame(
            SpfTerminalPolicy::SOFT_FAIL,
            $this->resolver->resolve(['qualifier' => '~', 'mechanism' => 'all'], true)
        );
    }

    public function test_neutral_mapping(): void
    {
        $this->assertSame(
            SpfTerminalPolicy::NEUTRAL,
            $this->resolver->resolve(['qualifier' => '?', 'mechanism' => 'all'], true)
        );
    }

    public function test_pass_all_mapping(): void
    {
        $this->assertSame(
            SpfTerminalPolicy::PASS_ALL,
            $this->resolver->resolve(['qualifier' => '+', 'mechanism' => 'all'], true)
        );
    }

    public function test_implicit_neutral_when_no_explicit_all(): void
    {
        $this->assertSame(
            SpfTerminalPolicy::IMPLICIT_NEUTRAL,
            $this->resolver->resolve(null, false)
        );
    }

    public function test_unknown_when_explicit_all_without_policy_data(): void
    {
        $this->assertSame(
            SpfTerminalPolicy::UNKNOWN,
            $this->resolver->resolve(null, true)
        );
    }
}
