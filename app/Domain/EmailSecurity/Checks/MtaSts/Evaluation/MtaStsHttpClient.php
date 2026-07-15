<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Evaluation;

use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsHttpClientInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetchResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetcher;
use Illuminate\Support\Facades\Http;

final class MtaStsHttpClient implements MtaStsHttpClientInterface
{
    private const CONNECT_TIMEOUT = 5;
    private const RESPONSE_TIMEOUT = 5;

    public function fetchPolicy(string $domain): MtaStsPolicyFetchResult
    {
        $url = MtaStsPolicyFetcher::policyUrl($domain);
        $start = microtime(true);

        try {
            $response = Http::withOptions([
                'verify' => true,
                'allow_redirects' => false,
                'connect_timeout' => self::CONNECT_TIMEOUT,
                'timeout' => self::RESPONSE_TIMEOUT,
            ])->get($url);

            $durationMs = (int) round((microtime(true) - $start) * 1000);
            $statusCode = $response->status();

            if ($statusCode >= 300 && $statusCode < 400) {
                return new MtaStsPolicyFetchResult(
                    url: $url,
                    status: MtaStsPolicyFetchResult::STATUS_REDIRECT,
                    httpStatus: $statusCode,
                    durationMs: $durationMs,
                    failureCategory: MtaStsPolicyFetchResult::STATUS_REDIRECT,
                );
            }

            if ($statusCode !== 200) {
                return new MtaStsPolicyFetchResult(
                    url: $url,
                    status: MtaStsPolicyFetchResult::STATUS_HTTP_NON_200,
                    httpStatus: $statusCode,
                    durationMs: $durationMs,
                    failureCategory: MtaStsPolicyFetchResult::STATUS_HTTP_NON_200,
                    bodyPreview: $this->previewBody((string) $response->body()),
                );
            }

            $body = (string) $response->body();
            if (strlen($body) > MtaStsPolicyFetcher::MAX_BODY_BYTES) {
                return new MtaStsPolicyFetchResult(
                    url: $url,
                    status: MtaStsPolicyFetchResult::STATUS_BODY_TOO_LARGE,
                    httpStatus: $statusCode,
                    durationMs: $durationMs,
                    failureCategory: MtaStsPolicyFetchResult::STATUS_BODY_TOO_LARGE,
                );
            }

            $contentType = $response->header('Content-Type');

            return new MtaStsPolicyFetchResult(
                url: $url,
                status: MtaStsPolicyFetchResult::STATUS_SUCCESS,
                httpStatus: $statusCode,
                contentType: is_string($contentType) ? $contentType : null,
                body: $body,
                durationMs: $durationMs,
                bodyPreview: $this->previewBody($body),
            );
        } catch (\Illuminate\Http\Client\ConnectionException $e) {
            return new MtaStsPolicyFetchResult(
                url: $url,
                status: MtaStsPolicyFetchResult::STATUS_CONNECTION_TIMEOUT,
                durationMs: (int) round((microtime(true) - $start) * 1000),
                failureCategory: MtaStsPolicyFetchResult::STATUS_CONNECTION_TIMEOUT,
            );
        } catch (\Throwable $e) {
            $message = strtolower($e->getMessage());
            $category = str_contains($message, 'certificate') || str_contains($message, 'ssl')
                ? MtaStsPolicyFetchResult::STATUS_CERTIFICATE_FAILURE
                : (str_contains($message, 'tls')
                    ? MtaStsPolicyFetchResult::STATUS_TLS_HANDSHAKE_FAILURE
                    : MtaStsPolicyFetchResult::STATUS_CONNECTION_TIMEOUT);

            return new MtaStsPolicyFetchResult(
                url: $url,
                status: $category,
                durationMs: (int) round((microtime(true) - $start) * 1000),
                failureCategory: $category,
            );
        }
    }

    private function previewBody(string $body): string
    {
        $stripped = strip_tags($body);

        return mb_substr(trim($stripped), 0, 200);
    }
}
