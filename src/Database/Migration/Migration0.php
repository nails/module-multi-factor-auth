<?php

/**
 * Migration:   0
 * Started:     23/02/2023
 */

namespace Nails\MFA\Database\Migration;

use Nails\Common\Interfaces;
use Nails\Common\Traits;

class Migration0 implements Interfaces\Database\Migration
{
    use Traits\Database\Migration;

    /**
     * Execute the migration
     *
     * @return Void
     */
    public function execute()
    {
        $this->query(
            <<<EOT
            CREATE TABLE `{{NAILS_DB_PREFIX}}mfa_token` (
                `id` int unsigned NOT NULL AUTO_INCREMENT,
                `user_id` int unsigned NOT NULL,
                `token` varchar(64) NOT NULL DEFAULT '',
                `salt` varchar(64) NOT NULL DEFAULT '',
                `ip` varchar(64) NOT NULL DEFAULT '',
                `expires` datetime DEFAULT NULL,
                `data` JSON DEFAULT NULL,
                `created` datetime NOT NULL,
                `created_by` int unsigned DEFAULT NULL,
                `modified` datetime NOT NULL,
                `modified_by` int unsigned DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `user_id` (`user_id`),
                KEY `created_by` (`created_by`),
                KEY `modified_by` (`modified_by`),
                CONSTRAINT `{{NAILS_DB_PREFIX}}mfa_token_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `{{NAILS_DB_PREFIX}}user` (`id`) ON DELETE CASCADE,
                CONSTRAINT `{{NAILS_DB_PREFIX}}mfa_token_ibfk_2` FOREIGN KEY (`created_by`) REFERENCES `{{NAILS_DB_PREFIX}}user` (`id`) ON DELETE SET NULL,
                CONSTRAINT `{{NAILS_DB_PREFIX}}mfa_token_ibfk_3` FOREIGN KEY (`modified_by`) REFERENCES `{{NAILS_DB_PREFIX}}user` (`id`) ON DELETE RESTRICT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
            EOT
        );
    }
}
