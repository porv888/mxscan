<?php

namespace Tests\Concerns;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Boots an in-memory SQLite schema for DMARC RUA tests.
 * Avoids RefreshDatabase because the full migration set is not runnable in this environment.
 */
trait UsesSqliteDmarcSchema
{
    protected function setUpSqliteDmarcSchema(): void
    {
        Config::set('database.default', 'sqlite');
        Config::set('database.connections.sqlite', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
            'foreign_key_constraints' => false,
        ]);

        DB::purge('sqlite');
        DB::reconnect('sqlite');

        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->string('role')->nullable();
            $table->string('status')->nullable();
            $table->rememberToken();
            $table->timestamps();
        });

        Schema::create('domains', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('domain')->unique();
            $table->string('environment')->default('prod');
            $table->string('provider_guess')->nullable();
            $table->integer('score_last')->nullable();
            $table->timestamp('last_scanned_at')->nullable();
            $table->string('status')->default('active');
            $table->string('dmarc_token', 32)->nullable()->unique();
            $table->timestamp('dmarc_last_report_at')->nullable();
            $table->timestamp('dmarc_rua_verified_at')->nullable();
            $table->timestamps();
        });

        Schema::create('scans', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->unsignedBigInteger('domain_id');
            $table->unsignedBigInteger('user_id');
            $table->string('type')->default('full');
            $table->string('status')->default('queued');
            $table->integer('progress_pct')->default(0);
            $table->integer('score')->nullable();
            $table->text('facts_json')->nullable();
            $table->text('result_json')->nullable();
            $table->text('recommendations_json')->nullable();
            $table->text('recommendations_md')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->bigInteger('duration_ms')->nullable();
            $table->timestamps();
        });

        Schema::create('dmarc_daily_stats', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('domain_id');
            $table->date('date');
            $table->unsignedBigInteger('total_count')->default(0);
            $table->unsignedBigInteger('aligned_count')->default(0);
            $table->unsignedBigInteger('dkim_pass_count')->default(0);
            $table->unsignedBigInteger('spf_pass_count')->default(0);
            $table->unsignedInteger('unique_sources')->default(0);
            $table->unsignedInteger('new_sources')->default(0);
            $table->unsignedInteger('report_count')->default(0);
            $table->timestamps();
        });

        Schema::create('dmarc_reports', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('domain_id');
            $table->string('org_name')->nullable();
            $table->timestamp('date_range_begin')->nullable();
            $table->unsignedInteger('total_count')->default(0);
            $table->timestamps();
        });

        Schema::create('dmarc_senders', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('domain_id');
            $table->string('source_ip', 45)->nullable();
            $table->string('header_from')->nullable();
            $table->string('org_name')->nullable();
            $table->unsignedBigInteger('total_count')->default(0);
            $table->unsignedBigInteger('aligned_count')->default(0);
            $table->unsignedBigInteger('dkim_pass_count')->default(0);
            $table->unsignedBigInteger('spf_pass_count')->default(0);
            $table->timestamp('first_seen_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->boolean('is_new')->default(false);
            $table->timestamps();
        });

        Schema::create('dmarc_events', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('domain_id');
            $table->string('type')->nullable();
            $table->string('severity')->nullable();
            $table->string('title')->nullable();
            $table->date('event_date')->nullable();
            $table->boolean('acknowledged')->default(false);
            $table->timestamps();
        });

        Schema::create('dmarc_alert_settings', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('domain_id');
            $table->unsignedBigInteger('user_id');
            $table->timestamps();
        });

        Schema::create('subscriptions', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->timestamps();
        });

        Schema::create('app_subscriptions', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->timestamps();
        });

        Schema::create('incidents', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('domain_id')->nullable();
            $table->unsignedBigInteger('delivery_check_id')->nullable();
            $table->string('type')->nullable();
            $table->string('kind')->nullable();
            $table->string('severity')->nullable();
            $table->text('message')->nullable();
            $table->text('meta')->nullable();
            $table->text('context')->nullable();
            $table->timestamp('occurred_at')->nullable();
            $table->timestamp('resolved_at')->nullable();
            $table->timestamps();
        });
    }

    protected function setUpSqliteMonitoringExtras(): void
    {
        Schema::create('blacklist_results', function (Blueprint $table) {
            $table->id();
            $table->uuid('scan_id');
            $table->string('provider')->nullable();
            $table->string('ip_address')->nullable();
            $table->string('status')->nullable();
            $table->text('message')->nullable();
            $table->string('removal_url')->nullable();
            $table->timestamps();
        });

        Schema::create('scan_snapshots', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('domain_id');
            $table->string('scan_type')->nullable();
            $table->boolean('mx_ok')->default(false);
            $table->boolean('spf_ok')->default(false);
            $table->integer('spf_lookups')->nullable();
            $table->boolean('dmarc_ok')->default(false);
            $table->boolean('tlsrpt_ok')->default(false);
            $table->boolean('mtasts_ok')->default(false);
            $table->text('rbl_hits')->nullable();
            $table->integer('score')->nullable();
            $table->timestamps();
        });

        Schema::create('scan_deltas', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('domain_id');
            $table->unsignedBigInteger('snapshot_id');
            $table->text('changes')->nullable();
            $table->timestamps();
        });

        Schema::create('jobs', function (Blueprint $table) {
            $table->id();
            $table->string('queue')->index();
            $table->longText('payload');
            $table->unsignedTinyInteger('attempts');
            $table->unsignedInteger('reserved_at')->nullable();
            $table->unsignedInteger('available_at');
            $table->unsignedInteger('created_at');
        });

        Schema::create('schedules', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('domain_id');
            $table->unsignedBigInteger('user_id');
            $table->string('scan_type')->nullable();
            $table->string('frequency')->nullable();
            $table->string('cron_expression')->nullable();
            $table->string('status')->nullable();
            $table->timestamp('next_run_at')->nullable();
            $table->timestamp('last_run_at')->nullable();
            $table->text('settings')->nullable();
            $table->timestamps();
        });

        Schema::create('delivery_monitors', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->unsignedBigInteger('domain_id');
            $table->string('label')->nullable();
            $table->string('inbox_address')->nullable();
            $table->string('token')->nullable();
            $table->string('status')->nullable();
            $table->timestamp('last_check_at')->nullable();
            $table->timestamp('last_incident_notified_at')->nullable();
            $table->timestamps();
        });

        Schema::create('spf_checks', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('domain_id');
            $table->integer('lookup_count')->nullable();
            $table->timestamps();
        });
    }
}
