<?php

namespace Database\Factories;

use App\Models\Domain;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\SpfCheck>
 */
class SpfCheckFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $lookups = $this->faker->numberBetween(0, 12);
        
        return [
            'domain_id' => Domain::factory(),
            'looked_up_record' => $this->faker->randomElement([
                'v=spf1 include:_spf.google.com ~all',
                'v=spf1 ip4:192.168.1.1 ip4:10.0.0.1 -all',
                'v=spf1 a mx include:mailgun.org ~all',
                null,
            ]),
            'lookup_count' => $lookups,
            'flattened_suggestion' => $lookups > 0 ? 'v=spf1 ip4:' . $this->faker->ipv4() . ' -all' : null,
            'warnings' => $this->faker->randomElement([
                [],
                ['High DNS lookup count'],
                ['No SPF record found'],
                ['PTR mechanism ignored']
            ]),
            'resolved_ips' => $this->faker->randomElement([
                [],
                [$this->faker->ipv4()],
                [$this->faker->ipv4(), $this->faker->ipv4()],
                [$this->faker->ipv4(), $this->faker->ipv6()]
            ]),
        ];
    }

    /**
     * Indicate that the SPF check has high lookup count.
     */
    public function highLookups(): static
    {
        return $this->state(fn (array $attributes) => [
            'lookup_count' => $this->faker->numberBetween(9, 12),
            'warnings' => ['High DNS lookup count: ' . $this->faker->numberBetween(9, 12) . '/10'],
        ]);
    }

    /**
     * Indicate that no SPF record was found.
     */
    public function noRecord(): static
    {
        return $this->state(fn (array $attributes) => [
            'looked_up_record' => null,
            'lookup_count' => 0,
            'flattened_suggestion' => null,
            'warnings' => ['No SPF record found'],
            'resolved_ips' => [],
        ]);
    }
}
