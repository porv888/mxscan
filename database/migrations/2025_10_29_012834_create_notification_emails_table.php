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
        Schema::create('notification_emails', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->string('email');
            $table->boolean('is_verified')->default(false);
            $table->string('verification_token')->nullable();
            $table->timestamp('verified_at')->nullable();
            $table->timestamps();

            // Indexes
            $table->index('user_id');
            $table->index(['user_id', 'email']);
            
            // Ensure unique email per user
            $table->unique(['user_id', 'email']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('notification_emails');
    }
};
