<?php

namespace Nails\MFA\Tests;

use Nails\MFA\Routes;
use PHPUnit\Framework\TestCase;

final class RoutesTest extends TestCase
{
    public function testTokenIsNotPartOfTheRoute(): void
    {
        self::assertSame(
            [
                'mfa'        => 'mfa/index',
                'mfa/manage' => 'mfa/manage',
            ],
            Routes::generate()
        );
    }
}
