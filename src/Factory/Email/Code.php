<?php

namespace Nails\MFA\Factory\Email;

use Nails\Email\Factory\Email;

class Code extends Email
{
    protected $sType = 'mfa_email_code';

    // --------------------------------------------------------------------------

    /**
     * @return array<mixed>
     */
    public function getTestData(): array
    {
        return [
            'code' => 123456,
        ];
    }
}
