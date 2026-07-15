<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Support;

final class BimiLogoRasterizer
{
    public function rasterize(string $svgBytes): ?string
    {
        $maxDimension = (int) config('bimi.preview.max_raster_dimension', 256);

        if (extension_loaded('imagick')) {
            $png = $this->rasterizeWithImagick($svgBytes, $maxDimension);
            if ($png !== null) {
                return $png;
            }
        }

        if (function_exists('imagecreatefromstring') && function_exists('imagepng')) {
            return $this->rasterizeWithGd($svgBytes, $maxDimension);
        }

        return null;
    }

    private function rasterizeWithImagick(string $svgBytes, int $maxDimension): ?string
    {
        try {
            $imagickClass = '\\Imagick';
            $imagick = new $imagickClass();
            $imagick->setBackgroundColor(new \ImagickPixel('transparent'));
            $imagick->readImageBlob($svgBytes);
            $imagick->setImageFormat('png32');

            $width = max(1, (int) $imagick->getImageWidth());
            $height = max(1, (int) $imagick->getImageHeight());
            $scale = min($maxDimension / $width, $maxDimension / $height, 1.0);
            if ($scale < 1.0) {
                $imagick->resizeImage(
                    max(1, (int) round($width * $scale)),
                    max(1, (int) round($height * $scale)),
                    \Imagick::FILTER_LANCZOS,
                    1,
                );
            }

            $png = (string) $imagick->getImageBlob();
            $imagick->clear();
            $imagick->destroy();

            return $png !== '' ? $png : null;
        } catch (\Throwable) {
            return null;
        }
    }

    private function rasterizeWithGd(string $svgBytes, int $maxDimension): ?string
    {
        $image = @imagecreatefromstring($svgBytes);
        if ($image === false) {
            return null;
        }

        $width = imagesx($image);
        $height = imagesy($image);
        if ($width <= 0 || $height <= 0) {
            imagedestroy($image);

            return null;
        }

        $scale = min($maxDimension / $width, $maxDimension / $height, 1.0);
        $targetWidth = max(1, (int) round($width * $scale));
        $targetHeight = max(1, (int) round($height * $scale));

        $canvas = imagecreatetruecolor($targetWidth, $targetHeight);
        if ($canvas === false) {
            imagedestroy($image);

            return null;
        }

        imagealphablending($canvas, false);
        imagesavealpha($canvas, true);
        $transparent = imagecolorallocatealpha($canvas, 0, 0, 0, 127);
        imagefill($canvas, 0, 0, $transparent);
        imagecopyresampled($canvas, $image, 0, 0, 0, 0, $targetWidth, $targetHeight, $width, $height);
        imagedestroy($image);

        ob_start();
        imagepng($canvas);
        $png = (string) ob_get_clean();
        imagedestroy($canvas);

        return $png !== '' ? $png : null;
    }
}
