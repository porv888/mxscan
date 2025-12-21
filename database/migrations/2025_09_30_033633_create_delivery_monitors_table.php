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
        Schema::create('delivery_monitors', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->foreignId('domain_id')->nullable()->constrained()->nullOnDelete();
            $table->string('label', 120);
            $table->string('inbox_address', 190)->unique();   // monitor+<token>@mxscan.me
            $table->string('token', 120)->unique();           // base64url token only
            $table->enum('status', ['active', 'paused'])->default('active');
            $table->timestamp('last_check_at')->nullable();
            $table->timestamp('last_incident_notified_at')->nullable();
            $table->timestamps();
            
            $table->index(['user_id', 'status']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('delivery_monitors');
    }
};
