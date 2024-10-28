<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

declare(strict_types=1);

namespace PSR7Sessions\Storageless\Http;

use Dflydev\FigCookies\Modifier\SameSite;
use Dflydev\FigCookies\SetCookie;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration as JwtConfig;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Configuration as FingerprintConfig;

/** @psalm-immutable */
final class Configuration
{
    private JwtConfig $jwtConfiguration;
    private Clock $clock;
    private SetCookie $cookie;
    /** @var positive-int */
    private int $idleTimeout = 43200;
    /** @var positive-int */
    private int $refreshTime = 60;
    /** @var literal-string */
    private string $sessionAttribute = SessionMiddleware::SESSION_ATTRIBUTE;
    private FingerprintConfig $clientFingerprintConfiguration;

    public function __construct(
        JwtConfig $jwtConfiguration,
    ) {
        $this->jwtConfiguration = clone $jwtConfiguration;

        $this->clock = SystemClock::fromSystemTimezone();

        $this->cookie = SetCookie::create('__Secure-slsession')
            ->withSecure(true)
            ->withHttpOnly(true)
            ->withSameSite(SameSite::lax())
            ->withPath('/');

        $this->clientFingerprintConfiguration = FingerprintConfig::disabled();
    }

    public function getJwtConfiguration(): JwtConfig
    {
        return $this->jwtConfiguration;
    }

    public function getClock(): Clock
    {
        return $this->clock;
    }

    public function getCookie(): SetCookie
    {
        return $this->cookie;
    }

    /** @return positive-int */
    public function getIdleTimeout(): int
    {
        return $this->idleTimeout;
    }

    /** @return positive-int */
    public function getRefreshTime(): int
    {
        return $this->refreshTime;
    }

    /** @return literal-string */
    public function getSessionAttribute(): string
    {
        return $this->sessionAttribute;
    }

    public function getClientFingerprintConfiguration(): FingerprintConfig
    {
        return $this->clientFingerprintConfiguration;
    }

    public function withJwtConfiguration(JwtConfig $jwtConfiguration): self
    {
        $new                   = clone $this;
        $new->jwtConfiguration = clone $jwtConfiguration;

        return $new;
    }

    public function withClock(Clock $clock): self
    {
        $new        = clone $this;
        $new->clock = $clock;

        return $new;
    }

    public function withCookie(SetCookie $cookie): self
    {
        $new         = clone $this;
        $new->cookie = clone $cookie;

        return $new;
    }

    /** @param positive-int $idleTimeout */
    public function withIdleTimeout(int $idleTimeout): self
    {
        $new              = clone $this;
        $new->idleTimeout = $idleTimeout;

        return $new;
    }

    /** @param positive-int $refreshTime */
    public function withRefreshTime(int $refreshTime): self
    {
        $new              = clone $this;
        $new->refreshTime = $refreshTime;

        return $new;
    }

    /** @param literal-string $sessionAttribute */
    public function withSessionAttribute(string $sessionAttribute): self
    {
        $new                   = clone $this;
        $new->sessionAttribute = $sessionAttribute;

        return $new;
    }

    public function withClientFingerprintConfiguration(FingerprintConfig $clientFingerprintConfiguration): self
    {
        $new                                 = clone $this;
        $new->clientFingerprintConfiguration = clone $clientFingerprintConfiguration;

        return $new;
    }
}
