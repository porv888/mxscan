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
        Schema::create('dmarc_senders', function (Blueprint $table) {
            $table->id();
            $table->foreignId('domain_id')->constrained()->onDelete('cascade');
            
            // Sender identification
            $table->string('source_ip', 45);
            $table->string('header_from')->nullable();
            $table->string('org_name')->nullable(); // Most common reporting org
            
            // Reverse DNS / PTR info (cached)
            $table->string('ptr_record')->nullable();
            $table->string('asn')->nullable();
            $table->string('asn_org')->nullable();
            
            // Aggregate metrics (updated on each report)
            $table->unsignedBigInteger('total_count')->default(0);
            $table->unsignedBigInteger('aligned_count')->default(0);
            $table->unsignedBigInteger('dkim_pass_count')->default(0);
            $table->unsignedBigInteger('spf_pass_count')->default(0);
            
            // Disposition breakdown
            $table->unsignedBigInteger('disposition_none')->default(0);
            $table->unsignedBigInteger('disposition_quarantine')->default(0);
            $table->unsignedBigInteger('disposition_reject')->default(0);
            
            // DKIM/SPF domains seen
            $table->string('dkim_domain')->nullable();
            $table->string('dkim_selector')->nullable();
            $table->string('spf_domain')->nullable();
            
            // Timestamps
            $table->timestamp('first_seen_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            
            // Risk assessment
            $table->boolean('is_new')->default(true); // New within last 7 days
            $table->boolean('is_risky')->default(false); // High fail rate
            
            $table->timestamps();
            
            // Unique constraint
            $table->unique(['domain_id', 'source_ip']);
            
            // Indexes
            $table->index(['domain_id', 'first_seen_at']);
            $table->index(['domain_id', 'last_seen_at']);
            $table->index(['domain_id', 'is_new']);
            $table->index(['domain_id', 'is_risky']);
            $table->index('source_ip');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dmarc_senders');
    }
};
