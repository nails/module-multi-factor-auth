<?php

namespace Nails\MFA\Tests;

use Nails\MFA\Console\Command\Config;
use Nails\MFA\Console\Command\Driver\Disable;
use Nails\MFA\Console\Command\Driver\Enable;
use Nails\MFA\Console\Command\Driver\Setting;
use Nails\MFA\Console\Command\Group\Policy;
use Nails\MFA\Console\Command\User\Method\Add;
use Nails\MFA\Console\Command\User\Method\DefaultMethod;
use Nails\MFA\Console\Command\User\Method\Remove;
use Nails\MFA\Console\Command\User\Status;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;

final class ConsoleCommandsTest extends TestCase
{
    /**
     * @return array<string, array{class-string<Command>, string}>
     */
    public static function commands(): array
    {
        return [
            'config'         => [Config::class, 'mfa:config'],
            'driver disable' => [Disable::class, 'mfa:driver:disable'],
            'driver enable'  => [Enable::class, 'mfa:driver:enable'],
            'driver setting' => [Setting::class, 'mfa:driver:setting'],
            'group policy'   => [Policy::class, 'mfa:group:policy'],
            'method add'     => [Add::class, 'mfa:user:method:add'],
            'method default' => [DefaultMethod::class, 'mfa:user:method:default'],
            'method remove'  => [Remove::class, 'mfa:user:method:remove'],
            'user status'    => [Status::class, 'mfa:user:status'],
        ];
    }

    // --------------------------------------------------------------------------

    /**
     * @param class-string<Command> $sClass
     */
    #[DataProvider('commands')]
    public function testCommandName(string $sClass, string $sExpected): void
    {
        self::assertSame($sExpected, (new $sClass())->getName());
    }
}
