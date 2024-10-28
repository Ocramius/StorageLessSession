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

namespace PSR7SessionsTest\Storageless\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use PSR7Sessions\Storageless\Session\LazySession;
use PSR7Sessions\Storageless\Session\SessionInterface;
use PSR7SessionsTest\Storageless\Asset\MakeSession;

use function uniqid;

#[CoversClass(LazySession::class)]
final class LazySessionTest extends TestCase
{
    /** @var SessionInterface&MockObject */
    private SessionInterface $wrappedSession;

    /** @var MakeSession&MockObject */
    private MakeSession $sessionLoader;

    private LazySession $lazySession;

    protected function setUp(): void
    {
        $this->wrappedSession = $this->createMock(SessionInterface::class);
        $this->sessionLoader  = $this->createMock(MakeSession::class);
        $this->lazySession    = LazySession::fromContainerBuildingCallback(function (): SessionInterface {
            return ($this->sessionLoader)();
        });
    }

    public function testLazyNonInitializedSessionIsAlwaysNotChanged(): void
    {
        $this->sessionLoader->expects(self::never())->method('__invoke');

        self::assertFalse($this->lazySession->hasChanged());
    }

    public function testHasChanged(): void
    {
        $this->wrappedSessionWillBeLoaded();

        $this
            ->wrappedSession
            ->expects(self::exactly(2))
            ->method('hasChanged')
            ->willReturnOnConsecutiveCalls(
                true,
                false,
            );

        $this->forceWrappedSessionInitialization();

        self::assertTrue($this->lazySession->hasChanged());
        self::assertFalse($this->lazySession->hasChanged());
    }

    public function testHas(): void
    {
        $this->wrappedSessionWillBeLoaded();

        $this->wrappedSession->expects(self::exactly(2))->method('has')->willReturnMap([
            ['foo', false],
            ['bar', true],
        ]);

        self::assertFalse($this->lazySession->has('foo'));
        self::assertTrue($this->lazySession->has('bar'));
    }

    public function testGet(): void
    {
        $this->wrappedSessionWillBeLoaded();

        $this->wrappedSession->expects(self::exactly(3))->method('get')->willReturnMap([
            ['foo', null, 'bar'],
            ['baz', null, 'tab'],
            ['baz', 'default', 'taz'],
        ]);

        self::assertSame('bar', $this->lazySession->get('foo'));
        self::assertSame('tab', $this->lazySession->get('baz'));
        self::assertSame('taz', $this->lazySession->get('baz', 'default'));
    }

    public function testRemove(): void
    {
        $this->wrappedSessionWillBeLoaded();

        $this->wrappedSession->expects(self::exactly(2))->method('remove')->with(self::logicalOr('foo', 'bar'));

        $this->lazySession->remove('foo');
        $this->lazySession->remove('bar');
    }

    public function testClear(): void
    {
        $this->wrappedSessionWillBeLoaded();

        $this->wrappedSession->expects(self::exactly(2))->method('clear');

        $this->lazySession->clear();
        $this->lazySession->clear();
    }

    public function testSet(): void
    {
        $this->wrappedSessionWillBeLoaded();

        $this
            ->wrappedSession
            ->expects(self::exactly(2))
            ->method('set')
            ->with(self::logicalOr('foo', 'baz'), self::logicalOr('bar', 'tab'));

        $this->lazySession->set('foo', 'bar');
        $this->lazySession->set('baz', 'tab');
    }

    public function testIsEmpty(): void
    {
        $this->wrappedSessionWillBeLoaded();

        $this
            ->wrappedSession
            ->expects(self::exactly(2))
            ->method('isEmpty')
            ->willReturnOnConsecutiveCalls(
                true,
                false,
            );

        self::assertTrue($this->lazySession->isEmpty());
        self::assertFalse($this->lazySession->isEmpty());
    }

    public function testJsonSerialize(): void
    {
        $this->wrappedSessionWillBeLoaded();

        $this
            ->wrappedSession
            ->expects(self::exactly(2))
            ->method('jsonSerialize')
            ->willReturnOnConsecutiveCalls(
                (object) ['foo' => 'bar'],
                (object) ['baz' => 'tab'],
            );

        self::assertEquals((object) ['foo' => 'bar'], $this->lazySession->jsonSerialize());
        self::assertEquals((object) ['baz' => 'tab'], $this->lazySession->jsonSerialize());
    }

    private function wrappedSessionWillBeLoaded(): void
    {
        $this->sessionLoader->expects(self::once())->method('__invoke')->willReturn($this->wrappedSession);
    }

    private function forceWrappedSessionInitialization(): void
    {
        // no-op operation that is known to trigger session lazy-loading
        $this->lazySession->remove(uniqid('nonExisting', true));
    }
}
