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
        Schema::create('dmarc_reports', function (Blueprint $table) {
            $table->id();
            $table->foreignId('domain_id')->constrained()->onDelete('cascade');
            $table->foreignId('dmarc_ingest_id')->nullable()->constrained()->onDelete('set null');
            
            // Report metadata from XML
            $table->string('org_name');
            $table->string('org_email')->nullable();
            $table->string('report_id');
            $table->timestamp('date_range_begin');
            $table->timestamp('date_range_end');
            
            // Published policy
            $table->string('policy_domain');
            $table->string('policy_adkim')->nullable(); // r=relaxed, s=strict
            $table->string('policy_aspf')->nullable();  // r=relaxed, s=strict
            $table->string('policy_p')->nullable();     // none, quarantine, reject
            $table->string('policy_sp')->nullable();    // subdomain policy
            $table->unsignedTinyInteger('policy_pct')->nullable(); // percentage
            
            // Aggregated stats for quick queries
            $table->unsignedInteger('total_count')->default(0);
            $table->unsignedInteger('pass_count')->default(0);
            $table->unsignedInteger('fail_count')->default(0);
            
            // Deduplication hash
            $table->string('report_hash', 64)->unique();
            
            $table->timestamps();
            
            // Indexes
            $table->index(['domain_id', 'date_range_begin']);
            $table->index(['domain_id', 'org_name']);
            $table->index('date_range_begin');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dmarc_reports');
    }
};
