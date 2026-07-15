<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

final class BimiSvgzDecompressor
{
    /**
     * @return array{
     *     success: bool,
     *     bytes: ?string,
     *     decompressed_bytes: int,
     *     errors: list<array{code: string, message: string}>
     * }
     */
    public function decompress(string $compressed): array
    {
        $maxDownload = (int) config('bimi.fetch.max_download_bytes', 65536);
        $maxDecompressed = (int) config('bimi.fetch.max_decompressed_bytes', 131072);

        if (strlen($compressed) > $maxDownload) {
            return $this->failure('COMPRESSED_TOO_LARGE', 'Compressed SVGZ exceeds maximum allowed size.');
        }

        if (!function_exists('gzdecode')) {
            return $this->failure('GZIP_UNAVAILABLE', 'GZIP decompression is unavailable.');
        }

        $decompressed = @gzdecode($compressed);
        if ($decompressed === false) {
            return $this->failure('GZIP_DECODE_FAILED', 'SVGZ payload could not be decompressed.');
        }

        if (strlen($decompressed) > $maxDecompressed) {
            return $this->failure('DECOMPRESSED_TOO_LARGE', 'Decompressed SVG exceeds maximum allowed size.');
        }

        if (str_contains($compressed, "\x1f\x8b\x1f\x8b")) {
            return $this->failure('CONCATENATED_GZIP', 'Concatenated gzip streams are not permitted.');
        }

        return [
            'success' => true,
            'bytes' => $decompressed,
            'decompressed_bytes' => strlen($decompressed),
            'errors' => [],
        ];
    }

    /**
     * @return array{success: false, bytes: null, decompressed_bytes: int, errors: list<array{code: string, message: string}>}
     */
    private function failure(string $code, string $message): array
    {
        return [
            'success' => false,
            'bytes' => null,
            'decompressed_bytes' => 0,
            'errors' => [[
                'code' => $code,
                'message' => $message,
            ]],
        ];
    }
}
