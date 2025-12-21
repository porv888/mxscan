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
        Schema::create('spf_checks', function (Blueprint $table) {
            $table->id();
            $table->foreignId('domain_id')->constrained()->onDelete('cascade');
            $table->text('looked_up_record')->nullable();
            $table->tinyInteger('lookup_count')->unsigned();
            $table->text('flattened_suggestion')->nullable();
            $table->json('warnings')->nullable();
            $table->json('resolved_ips')->nullable();
            $table->boolean('changed')->default(false);
            $table->timestamps();
            
            // Composite index for efficient queries
            $table->index(['domain_id', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('spf_checks');
    }
};
