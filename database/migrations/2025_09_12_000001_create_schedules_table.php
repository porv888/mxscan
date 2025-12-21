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
        if (Schema::hasTable('schedules')) {
            return;
        }

        Schema::create('schedules', function (Blueprint $table) {
            $table->id();
            $table->foreignId('domain_id')->constrained()->onDelete('cascade');
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->set('scan_type', ['dns_security', 'blacklist', 'both'])->default('dns_security');
            $table->enum('frequency', ['daily', 'weekly', 'monthly', 'custom'])->default('weekly');
            $table->string('cron_expression')->nullable()->comment('For custom frequency');
            $table->timestamp('next_run_at')->nullable();
            $table->timestamp('last_run_at')->nullable();
            $table->enum('status', ['active', 'paused', 'disabled'])->default('active');
            $table->json('settings')->nullable()->comment('Additional scan settings');
            $table->timestamps();
            
            // Indexes
            $table->index('domain_id');
            $table->index('user_id');
            $table->index('status');
            $table->index('next_run_at');
            $table->index(['status', 'next_run_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('schedules');
    }
};