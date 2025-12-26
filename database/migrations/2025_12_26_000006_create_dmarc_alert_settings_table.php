<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('dmarc_alert_settings', function (Blueprint $table) {
            $table->id();
            $table->foreignId('domain_id')->constrained()->onDelete('cascade');
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            
            // Alert toggles
            $table->boolean('new_sender_enabled')->default(true);
            $table->boolean('fail_spike_enabled')->default(true);
            $table->boolean('alignment_drop_enabled')->default(true);
            $table->boolean('dkim_fail_spike_enabled')->default(true);
            $table->boolean('spf_fail_spike_enabled')->default(true);
            
            // Thresholds
            $table->unsignedTinyInteger('spike_threshold_pct')->default(15); // % increase to trigger spike
            $table->unsignedInteger('min_volume_threshold')->default(100); // Minimum volume for spike detection
            $table->unsignedTinyInteger('new_sender_days')->default(7); // Days to consider sender "new"
            
            // Throttling
            $table->unsignedSmallInteger('throttle_hours')->default(6); // Hours between same alert type
            
            // Last alert timestamps for throttling
            $table->timestamp('last_new_sender_alert')->nullable();
            $table->timestamp('last_fail_spike_alert')->nullable();
            $table->timestamp('last_alignment_drop_alert')->nullable();
            $table->timestamp('last_dkim_fail_spike_alert')->nullable();
            $table->timestamp('last_spf_fail_spike_alert')->nullable();
            
            $table->timestamps();
            
            // Unique constraint - one setting per domain per user
            $table->unique(['domain_id', 'user_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dmarc_alert_settings');
    }
};
