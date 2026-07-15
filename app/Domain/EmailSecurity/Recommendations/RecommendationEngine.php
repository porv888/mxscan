<?php

namespace App\Domain\EmailSecurity\Recommendations;

use App\Domain\EmailSecurity\Contracts\RecommendationEngineInterface;
use App\Domain\EmailSecurity\DTO\RecommendationListDTO;
use App\Domain\EmailSecurity\DTO\ScanResultDTO;
use App\Models\Domain;

final class RecommendationEngine implements RecommendationEngineInterface
{
    public function __construct(
        private ScanRecommendationService $recommendationService,
        private RecommendationCollectionGuard $collectionGuard,
    ) {
    }

    public function build(Domain $domain, ScanResultDTO $scanResult): RecommendationListDTO
    {
        $resultJson = $scanResult->toArray();
        $records = $resultJson['dns']['records'] ?? null;

        $items = $this->collectionGuard->deduplicate(
            $this->recommendationService->build($domain, $resultJson, $records)
        );
        $allClear = $this->recommendationService->evaluateAllClear($resultJson, $records);

        return new RecommendationListDTO(items: $items, allClear: $allClear);
    }
}
