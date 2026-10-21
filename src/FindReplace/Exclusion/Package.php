<?php

namespace Nails\MFA\FindReplace\Exclusion;

use Nails\FindReplace\Interfaces\Exclusion;

class Package implements Exclusion
{
    public function hidden(): array
    {
        return [
            NAILS_DB_PREFIX . 'mfa_token',
            NAILS_DB_PREFIX . 'mfa_user_method',
        ];
    }

    public function readOnly(): array
    {
        return [];
    }
}
