<?php

namespace Database\Factories;

use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Scan>
 */
class ScanFactory extends Factory
{
    protected $model = Scan::class;

    public function definition(): array
    {
        return [
            'domain_id' => Domain::factory(),
            'user_id' => User::factory(),
            'type' => 'full',
            'status' => 'finished',
            'progress_pct' => 100,
            'score' => fake()->numberBetween(40, 95),
            'started_at' => now()->subMinutes(5),
            'finished_at' => now(),
            'duration_ms' => fake()->numberBetween(500, 5000),
        ];
    }
}
