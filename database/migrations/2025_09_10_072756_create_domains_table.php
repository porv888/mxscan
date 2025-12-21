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
        Schema::create('domains', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->string('domain')->unique();
            $table->enum('environment', ['prod', 'dev'])->default('prod');
            $table->string('provider_guess')->nullable();
            $table->integer('score_last')->nullable();
            $table->timestamp('last_scanned_at')->nullable();
            $table->enum('status', ['active', 'disabled', 'pending'])->default('active');
            $table->timestamps();
            
            // Add indexes
            $table->index('user_id');
            $table->index('domain');
            $table->index('environment');
            $table->index('status');
            $table->index('last_scanned_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('domains');
    }
};
