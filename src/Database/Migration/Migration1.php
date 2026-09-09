<?php

/**
 * Migration:   1
 * Started:     09/09/2026
 */

namespace Nails\MFA\Database\Migration;

use Nails\Common\Interfaces;
use Nails\Common\Traits;

class Migration1 implements Interfaces\Database\Migration
{
    use Traits\Database\Migration;

    /**
     * Execute the migration
     *
     * @return void
     */
    public function execute()
    {
        $this->query(
            <<<'EOT'
            ALTER TABLE `{{NAILS_DB_PREFIX}}mfa_token`
                ADD COLUMN `attempts` int unsigned NOT NULL DEFAULT 0 AFTER `salt`,
                ADD COLUMN `is_deleted` tinyint(1) unsigned NOT NULL DEFAULT 0 AFTER `data`,
                ADD KEY `user_created` (`user_id`, `created`);
            EOT
        );
    }
}
