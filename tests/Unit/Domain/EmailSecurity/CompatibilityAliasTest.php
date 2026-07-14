<?php

namespace Tests\Unit\Domain\EmailSecurity;

use ReflectionClass;
use Tests\TestCase;

class CompatibilityAliasTest extends TestCase
{
    public function test_scan_recommendation_service_alias_extends_domain_implementation(): void
    {
        $legacy = new \App\Services\ScanReport\ScanRecommendationService();
        $parent = (new ReflectionClass($legacy))->getParentClass();

        $this->assertNotNull($parent);
        $this->assertSame(
            \App\Domain\EmailSecurity\Recommendations\ScanRecommendationService::class,
            $parent->getName()
        );
        $this->assertNotSame($parent->getName(), \App\Services\ScanReport\ScanRecommendationService::class);
    }

    public function test_scan_report_status_mapper_alias_extends_domain_implementation(): void
    {
        $legacy = new \App\Services\ScanReport\ScanReportStatusMapper();
        $parent = (new ReflectionClass($legacy))->getParentClass();

        $this->assertNotNull($parent);
        $this->assertSame(
            \App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper::class,
            $parent->getName()
        );
        $this->assertNotSame($parent->getName(), \App\Services\ScanReport\ScanReportStatusMapper::class);
    }

    public function test_compatibility_aliases_are_not_self_extending_shims(): void
    {
        foreach ([
            \App\Services\ScanReport\ScanRecommendationService::class,
            \App\Services\ScanReport\ScanReportStatusMapper::class,
        ] as $class) {
            $reflection = new ReflectionClass($class);
            $this->assertFalse($reflection->getName() === $reflection->getParentClass()?->getName());
            $this->assertGreaterThan(5, strlen((string) file_get_contents($reflection->getFileName())));
        }
    }

    public function test_domain_implementations_are_authoritative_classes(): void
    {
        $rec = new ReflectionClass(\App\Domain\EmailSecurity\Recommendations\ScanRecommendationService::class);
        $mapper = new ReflectionClass(\App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper::class);

        $this->assertFalse($rec->isSubclassOf(\App\Services\ScanReport\ScanRecommendationService::class));
        $this->assertFalse($mapper->isSubclassOf(\App\Services\ScanReport\ScanReportStatusMapper::class));
        $this->assertTrue($rec->hasMethod('build'));
        $this->assertTrue($mapper->hasMethod('mapDmarc'));
    }
}
