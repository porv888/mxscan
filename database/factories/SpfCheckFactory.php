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
            'domain' => $this->faker->domainName(),
            'current_record' => $this->faker->randomElement([
                'v=spf1 include:_spf.google.com ~all',
                'v=spf1 ip4:192.168.1.1 ip4:10.0.0.1 -all',
                'v=spf1 a mx include:mailgun.org ~all',
                null
            ]),
            'lookups_used' => $lookups,
            'flattened_spf' => $lookups > 0 ? 'v=spf1 ip4:' . $this->faker->ipv4() . ' -all' : null,
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
            'checked_at' => $this->faker->dateTimeBetween('-30 days', 'now'),
        ];
    }

    /**
     * Indicate that the SPF check has high lookup count.
     */
    public function highLookups(): static
    {
        return $this->state(fn (array $attributes) => [
            'lookups_used' => $this->faker->numberBetween(9, 12),
            'warnings' => ['High DNS lookup count: ' . $this->faker->numberBetween(9, 12) . '/10'],
        ]);
    }

    /**
     * Indicate that no SPF record was found.
     */
    public function noRecord(): static
    {
        return $this->state(fn (array $attributes) => [
            'current_record' => null,
            'lookups_used' => 0,
            'flattened_spf' => null,
            'warnings' => ['No SPF record found'],
            'resolved_ips' => [],
        ]);
    }
}
