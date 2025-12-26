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
        Schema::create('dmarc_daily_stats', function (Blueprint $table) {
            $table->id();
            $table->foreignId('domain_id')->constrained()->onDelete('cascade');
            $table->date('date');
            
            // Volume metrics
            $table->unsignedInteger('total_count')->default(0);
            $table->unsignedInteger('aligned_count')->default(0);
            $table->unsignedInteger('dkim_pass_count')->default(0);
            $table->unsignedInteger('spf_pass_count')->default(0);
            
            // Disposition breakdown
            $table->unsignedInteger('disposition_none')->default(0);
            $table->unsignedInteger('disposition_quarantine')->default(0);
            $table->unsignedInteger('disposition_reject')->default(0);
            
            // Calculated rates (stored for fast queries, 0-100 scale)
            $table->decimal('alignment_rate', 5, 2)->default(0);
            $table->decimal('dkim_pass_rate', 5, 2)->default(0);
            $table->decimal('spf_pass_rate', 5, 2)->default(0);
            
            // Unique sender count for the day
            $table->unsignedInteger('unique_sources')->default(0);
            $table->unsignedInteger('new_sources')->default(0);
            
            // Report count
            $table->unsignedInteger('report_count')->default(0);
            
            $table->timestamps();
            
            // Unique constraint
            $table->unique(['domain_id', 'date']);
            
            // Indexes
            $table->index('date');
            $table->index(['domain_id', 'date']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dmarc_daily_stats');
    }
};
