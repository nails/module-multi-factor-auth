<?php

namespace Nails\MFA\Tests;

use Nails\MFA\Service\MultiFactorAuth;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

final class MultiFactorAuthSignalTest extends TestCase
{
    private const int NOW     = 1_700_000_000;
    private const int USER_ID = 42;

    // --------------------------------------------------------------------------

    /**
     * @param array<string, mixed> $aOverrides
     */
    private static function signal(array $aOverrides = []): stdClass
    {
        return (object) array_merge([
            'method'        => 'passkey',
            'user_id'       => self::USER_ID,
            'user_verified' => true,
            'at'            => self::NOW - 10,
        ], $aOverrides);
    }

    // --------------------------------------------------------------------------

    /**
     * @return array<string, array{stdClass|null, int, bool}>
     */
    public static function signals(): array
    {
        return [
            'fresh user-verified passkey for the same user' => [self::signal(), self::USER_ID, true],
            'at the freshness boundary (inclusive)'         => [self::signal(['at' => self::NOW - MultiFactorAuth::LOGIN_SIGNAL_MAX_AGE]), self::USER_ID, true],
            'no signal at all'                              => [null, self::USER_ID, false],
            'password login'                               => [self::signal(['method' => 'password']), self::USER_ID, false],
            'unknown method'                               => [self::signal(['method' => 'carrier-pigeon']), self::USER_ID, false],
            'passkey but not user-verified'                => [self::signal(['user_verified' => false]), self::USER_ID, false],
            'passkey for a different user'                 => [self::signal(['user_id' => 99]), self::USER_ID, false],
            'stale signal, one second past the window'     => [self::signal(['at' => self::NOW - MultiFactorAuth::LOGIN_SIGNAL_MAX_AGE - 1]), self::USER_ID, false],
            'signal timestamped in the future'            => [self::signal(['at' => self::NOW + 5]), self::USER_ID, false],
            'signal with no timestamp'                    => [self::signal(['at' => 0]), self::USER_ID, false],
            'signal with a missing method property'       => [(object) ['user_id' => self::USER_ID, 'user_verified' => true, 'at' => self::NOW], self::USER_ID, false],
            'target user id of zero'                      => [self::signal(['user_id' => 0]), 0, false],
        ];
    }

    // --------------------------------------------------------------------------

    #[DataProvider('signals')]
    public function testLoginSignalSatisfies(?stdClass $oSignal, int $iUserId, bool $bExpected): void
    {
        self::assertSame(
            $bExpected,
            MultiFactorAuth::loginSignalSatisfies($oSignal, $iUserId, self::NOW)
        );
    }
}
