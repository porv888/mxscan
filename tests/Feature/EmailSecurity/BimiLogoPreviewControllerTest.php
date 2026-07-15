<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiIndicatorPreviewStore;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Storage;
use Tests\Support\EmailSecurity\BimiTestFixtures;
use Tests\TestCase;

class BimiLogoPreviewControllerTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Storage::fake('local');
    }

    public function test_owner_can_view_preview(): void
    {
        [$user, $domain, $scan] = $this->seedOwnedScan();
        $sha256 = BimiTestFixtures::validSvgSha256();
        app(BimiIndicatorPreviewStore::class)->store($scan->id, $sha256, BimiTestFixtures::VALID_SVG);

        $response = $this->actingAs($user)->get(route('domains.bimi.preview', [$domain, $scan]));

        $response->assertOk();
        $this->assertContains($response->headers->get('Content-Type'), ['image/png', 'image/svg+xml']);
        $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }

    public function test_other_user_is_forbidden(): void
    {
        [$user, $domain, $scan] = $this->seedOwnedScan();
        $other = User::factory()->create();

        $this->actingAs($other)->get(route('domains.bimi.preview', [$domain, $scan]))->assertForbidden();
        unset($user);
    }

    public function test_missing_cache_returns_not_found(): void
    {
        [$user, $domain, $scan] = $this->seedOwnedScan();

        $this->actingAs($user)->get(route('domains.bimi.preview', [$domain, $scan]))->assertNotFound();
    }

    public function test_invalid_indicator_returns_not_found(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);
        $scan = Scan::factory()->create([
            'user_id' => $user->id,
            'domain_id' => $domain->id,
            'status' => 'finished',
            'result_json' => [
                'bimi' => [
                    'analysis' => [
                        'version' => 'bimi-native-v1',
                        'indicator' => ['status' => 'invalid', 'sha256' => BimiTestFixtures::validSvgSha256()],
                    ],
                ],
            ],
        ]);

        $this->actingAs($user)->get(route('domains.bimi.preview', [$domain, $scan]))->assertNotFound();
    }

    /**
     * @return array{0: User, 1: Domain, 2: Scan}
     */
    private function seedOwnedScan(): array
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id, 'domain' => 'preview-owner.test']);
        $sha256 = BimiTestFixtures::validSvgSha256();
        $scan = Scan::factory()->create([
            'user_id' => $user->id,
            'domain_id' => $domain->id,
            'status' => 'finished',
            'result_json' => [
                'bimi' => [
                    'analysis' => [
                        'version' => 'bimi-native-v1',
                        'indicator' => [
                            'status' => 'valid',
                            'sha256' => $sha256,
                            'preview_ref' => [
                                'scan_id' => null,
                                'sha256' => $sha256,
                            ],
                        ],
                    ],
                ],
            ],
        ]);
        $resultJson = $scan->result_json;
        $resultJson['bimi']['analysis']['indicator']['preview_ref']['scan_id'] = $scan->id;
        $scan->update(['result_json' => $resultJson]);
        $scan->refresh();

        return [$user, $domain, $scan];
    }
}
