<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\DeliveryCheck;
use App\Services\EmailAuthEvaluator;

class BackfillDeliveryAuth extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'delivery:backfill-auth {limit=100}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Populate SPF/DKIM/DMARC for recent checks with null auth_meta';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $limit = (int)$this->argument('limit');
        $q = DeliveryCheck::where(function($q){
            $q->whereNull('spf_pass')
              ->orWhereNull('dkim_pass')
              ->orWhereNull('dmarc_pass')
              ->orWhereNull('auth_meta');
        })->latest()->take($limit)->get();
        $this->info("Backfilling {$q->count()} checks…");

        $svc = app(EmailAuthEvaluator::class);
        $processed = 0;
        $failed = 0;

        foreach ($q as $c) {
            try {
                $auth = $svc->evaluate([
                    'raw_headers'   => $c->raw_headers,
                    'raw_body'      => $c->raw_body,
                    'header_from'   => $c->from_addr,
                    'envelope_from' => $c->from_addr,
                ]);
                
                $c->auth_meta  = $auth;
                $c->spf_pass   = array_key_exists('pass', $auth['spf'] ?? []) ? $auth['spf']['pass'] : null;
                $c->dkim_pass  = array_key_exists('pass', $auth['dkim'] ?? []) ? $auth['dkim']['pass'] : null;
                $c->dmarc_pass = array_key_exists('pass', $auth['dmarc'] ?? []) ? $auth['dmarc']['pass'] : null;
                
                // Update TTI and MX info if available
                if (isset($auth['metrics']['tti_ms']) && $c->tti_ms === null) {
                    $c->tti_ms = $auth['metrics']['tti_ms'];
                }
                if (isset($auth['analysis']['mx_host']) && $c->mx_host === null) {
                    $c->mx_host = $auth['analysis']['mx_host'];
                }
                if (isset($auth['analysis']['mx_ip']) && $c->mx_ip === null) {
                    $c->mx_ip = $auth['analysis']['mx_ip'];
                }
                
                // Update verdict based on auth results
                if ($c->spf_pass === false || $c->dkim_pass === false || $c->dmarc_pass === false) {
                    $c->verdict = 'incident';
                } elseif ($c->tti_ms !== null && $c->tti_ms > 900000) {
                    $c->verdict = 'warning';
                } else {
                    $c->verdict = 'ok';
                }
                
                $c->save();
                $processed++;
                
                if ($this->option('verbose')) {
                    $this->line("✓ Check {$c->id}: SPF={$this->formatBool($c->spf_pass)} DKIM={$this->formatBool($c->dkim_pass)} DMARC={$this->formatBool($c->dmarc_pass)}");
                }
            } catch (\Throwable $e) {
                $this->error("✗ Check {$c->id} failed: ".$e->getMessage());
                $failed++;
            }
        }

        $this->info("\nBackfill complete: {$processed} processed, {$failed} failed");
        return 0;
    }
    
    /**
     * Format boolean for display
     */
    protected function formatBool(?bool $value): string
    {
        return is_null($value) ? 'none' : ($value ? 'pass' : 'fail');
    }
}
