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
        Schema::create('dmarc_records', function (Blueprint $table) {
            $table->id();
            $table->foreignId('dmarc_report_id')->constrained()->onDelete('cascade');
            $table->foreignId('domain_id')->constrained()->onDelete('cascade');
            
            // Source information
            $table->string('source_ip', 45); // IPv4 or IPv6
            $table->unsignedInteger('count')->default(1);
            
            // Policy evaluation
            $table->string('disposition')->nullable(); // none, quarantine, reject
            
            // DKIM results
            $table->string('dkim_result')->nullable(); // pass, fail, none
            $table->string('dkim_domain')->nullable();
            $table->string('dkim_selector')->nullable();
            $table->boolean('dkim_aligned')->default(false);
            
            // SPF results
            $table->string('spf_result')->nullable(); // pass, fail, softfail, neutral, none, temperror, permerror
            $table->string('spf_domain')->nullable();
            $table->boolean('spf_aligned')->default(false);
            
            // Header from
            $table->string('header_from')->nullable();
            $table->string('envelope_from')->nullable();
            
            // Overall alignment (either DKIM or SPF aligned = pass)
            $table->boolean('aligned')->default(false);
            
            // Deduplication hash for this specific record
            $table->string('record_hash', 64);
            
            // Date for easier time-based queries (denormalized from report)
            $table->date('report_date');
            
            $table->timestamps();
            
            // Indexes for common queries
            $table->index(['domain_id', 'report_date']);
            $table->index(['domain_id', 'source_ip']);
            $table->index(['domain_id', 'aligned']);
            $table->index('source_ip');
            $table->index('report_date');
            
            // Prevent duplicate records
            $table->unique(['dmarc_report_id', 'record_hash']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dmarc_records');
    }
};
