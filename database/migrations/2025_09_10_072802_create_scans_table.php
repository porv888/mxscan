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
        Schema::create('scans', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignId('domain_id')->constrained()->onDelete('cascade');
            $table->foreignId('user_id')->constrained();
            $table->enum('status', ['queued', 'running', 'finished', 'failed'])->default('queued');
            $table->integer('progress_pct')->default(0);
            $table->integer('score')->nullable();
            $table->longText('facts_json')->nullable();
            $table->longText('result_json')->nullable();
            $table->longText('recommendations_md')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->bigInteger('duration_ms')->nullable();
            $table->timestamps();
            
            // Add indexes
            $table->index('domain_id');
            $table->index('user_id');
            $table->index('status');
            $table->index('started_at');
            $table->index('finished_at');
            $table->index(['domain_id', 'status']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scans');
    }
};
