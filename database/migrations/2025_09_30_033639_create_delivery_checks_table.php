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
        Schema::create('delivery_checks', function (Blueprint $table) {
            $table->id();
            $table->foreignId('delivery_monitor_id')->constrained()->cascadeOnDelete();
            $table->string('message_id', 255)->nullable();
            $table->timestamp('received_at')->nullable();
            $table->string('from_addr', 255)->nullable();
            $table->string('to_addr', 255)->nullable();
            $table->string('subject', 255)->nullable();

            // Parsed auth results (from Authentication-Results)
            $table->boolean('spf_pass')->nullable();
            $table->boolean('dkim_pass')->nullable();
            $table->boolean('dmarc_pass')->nullable();

            $table->integer('tti_ms')->nullable();            // Time-to-inbox
            $table->string('mx_host', 255)->nullable();
            $table->string('mx_ip', 64)->nullable();

            $table->enum('verdict', ['ok', 'warning', 'incident'])->default('ok');
            $table->json('raw_headers')->nullable();          // optional for debugging
            $table->timestamps();

            $table->index(['delivery_monitor_id', 'received_at']);
            $table->index(['delivery_monitor_id', 'verdict', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('delivery_checks');
    }
};
