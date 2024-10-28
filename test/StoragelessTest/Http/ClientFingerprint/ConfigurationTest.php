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

namespace PSR7SessionsTest\Storageless\Http\ClientFingerprint;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Configuration;
use PSR7Sessions\Storageless\Http\ClientFingerprint\RemoteAddr;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Source;
use PSR7Sessions\Storageless\Http\ClientFingerprint\UserAgent;

use function array_map;

#[CoversClass(Configuration::class)]
final class ConfigurationTest extends TestCase
{
    public function testDisabled(): void
    {
        $configuration = Configuration::disabled();

        self::assertSame([], $configuration->sources());
    }

    public function testCustomSourcesFactory(): void
    {
        $source = $this->createMock(Source::class);

        $configuration = Configuration::forSources($source);

        self::assertSame([$source], $configuration->sources());
    }

    public function testEnabledFactoryProvidesRemoteAddrAndUserAgentSources(): void
    {
        $configuration = Configuration::forIpAndUserAgent();

        $sources = array_map(
            static fn (Source $source) => $source::class,
            $configuration->sources(),
        );

        self::assertContains(RemoteAddr::class, $sources);
        self::assertContains(UserAgent::class, $sources);
    }
}
