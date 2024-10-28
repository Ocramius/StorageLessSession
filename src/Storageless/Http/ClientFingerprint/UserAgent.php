<?php

declare(strict_types=1);

namespace PSR7Sessions\Storageless\Http\ClientFingerprint;

use Psr\Http\Message\ServerRequestInterface;

final readonly class UserAgent implements Source
{
    public function extractFrom(ServerRequestInterface $request): string
    {
        $userAgent = $request->getHeaderLine('user-agent');

        if ($userAgent === '') {
            throw SourceMissing::for('user-agent');
        }

        return $userAgent;
    }
}
