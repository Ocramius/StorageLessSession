<?php

declare(strict_types=1);

namespace PSR7Sessions\Storageless\Http\ClientFingerprint;

use Psr\Http\Message\ServerRequestInterface;

use function array_key_exists;
use function is_string;

final readonly class RemoteAddr implements Source
{
    private const SERVER_PARAM_NAME = 'REMOTE_ADDR';

    public function extractFrom(ServerRequestInterface $request): string
    {
        $serverParams = $request->getServerParams();
        if (
            ! array_key_exists(self::SERVER_PARAM_NAME, $serverParams)
            || ! is_string($serverParams[self::SERVER_PARAM_NAME])
            || $serverParams[self::SERVER_PARAM_NAME] === ''
        ) {
            throw SourceMissing::for(self::SERVER_PARAM_NAME);
        }

        return $serverParams[self::SERVER_PARAM_NAME];
    }
}
