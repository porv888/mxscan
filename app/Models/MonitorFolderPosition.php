<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class MonitorFolderPosition extends Model
{
    protected $fillable = [
        'folder_name',
        'last_uid',
    ];

    protected $casts = [
        'last_uid' => 'integer',
    ];

    /**
     * Get or create a folder position record
     */
    public static function getPosition(string $folderName): self
    {
        return static::firstOrCreate(
            ['folder_name' => $folderName],
            ['last_uid' => 0]
        );
    }

    /**
     * Update the last UID for this folder
     */
    public function updateLastUid(int $uid): void
    {
        if ($uid > $this->last_uid) {
            $this->update(['last_uid' => $uid]);
        }
    }
}
