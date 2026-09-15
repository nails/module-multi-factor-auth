<?php

namespace Nails\MFA\Housekeeping;

use Nails\Common\Model\Base as ModelBase;
use Nails\Factory;
use Nails\Housekeeping\Routine\Base;
use Nails\Housekeeping\Traits\DeletesModelRows;
use Nails\MFA\Constants;

class Tokens extends Base
{
    use DeletesModelRows;

    const LABEL           = 'MFA tokens';
    const DESCRIPTION     = 'Deletes expired multi-factor authentication challenge tokens';
    const CRON_EXPRESSION = '*/15 * * * *';

    protected function model(): ModelBase
    {
        return Factory::model('Token', Constants::MODULE_SLUG);
    }

    /**
     * @return array<int, mixed>
     */
    protected function where(): array
    {
        /** @var \DateTime $oNow */
        $oNow = Factory::factory('DateTime');

        return [
            ['expires <', $oNow->format('Y-m-d H:i:s')],
        ];
    }

    /**
     * @return string[]
     */
    protected function auditColumns(): array
    {
        return ['id', 'user_id', 'expires'];
    }
}
