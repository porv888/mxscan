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
        Schema::create('dmarc_events', function (Blueprint $table) {
            $table->id();
            $table->foreignId('domain_id')->constrained()->onDelete('cascade');
            
            // Event type: new_sender, fail_spike, alignment_drop, dkim_fail_spike, spf_fail_spike, policy_change
            $table->string('type');
            $table->string('severity')->default('warning'); // info, warning, critical
            
            // Event details
            $table->string('title');
            $table->text('description')->nullable();
            $table->json('meta')->nullable(); // Additional context (IP, rates, etc.)
            
            // Related entities
            $table->foreignId('dmarc_sender_id')->nullable()->constrained()->onDelete('set null');
            $table->string('source_ip', 45)->nullable();
            
            // Metrics at time of event
            $table->decimal('previous_rate', 5, 2)->nullable();
            $table->decimal('current_rate', 5, 2)->nullable();
            $table->unsignedInteger('volume')->nullable();
            
            // Event date
            $table->date('event_date');
            
            // Notification tracking
            $table->boolean('notified')->default(false);
            $table->timestamp('notified_at')->nullable();
            
            // Acknowledgement
            $table->boolean('acknowledged')->default(false);
            $table->timestamp('acknowledged_at')->nullable();
            $table->foreignId('acknowledged_by')->nullable()->constrained('users')->onDelete('set null');
            
            $table->timestamps();
            
            // Indexes
            $table->index(['domain_id', 'type']);
            $table->index(['domain_id', 'event_date']);
            $table->index(['domain_id', 'notified']);
            $table->index('event_date');
            $table->index('type');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dmarc_events');
    }
};
