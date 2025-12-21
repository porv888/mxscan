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
        Schema::create('audit_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->nullable()->constrained()->onDelete('set null');
            $table->string('action');
            $table->string('model_type')->nullable()->comment('Model class name');
            $table->unsignedBigInteger('model_id')->nullable()->comment('Model ID');
            $table->json('old_values')->nullable()->comment('Previous values');
            $table->json('new_values')->nullable()->comment('New values');
            $table->string('ip_address', 50)->nullable();
            $table->text('user_agent')->nullable();
            $table->string('url')->nullable();
            $table->string('method', 10)->nullable()->comment('HTTP method');
            $table->timestamps();
            
            // Indexes
            $table->index('user_id');
            $table->index('action');
            $table->index('model_type');
            $table->index('model_id');
            $table->index('created_at');
            $table->index(['user_id', 'action']);
            $table->index(['model_type', 'model_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('audit_logs');
    }
};