<?php

/**
 * Migration:   2
 * Started:     09/09/2026
 */

namespace Nails\MFA\Database\Migration;

use Nails\Common\Interfaces;
use Nails\Common\Traits;

class Migration2 implements Interfaces\Database\Migration
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
            CREATE TABLE `{{NAILS_DB_PREFIX}}mfa_group_policy` (
                `id` int unsigned NOT NULL AUTO_INCREMENT,
                `group_id` int unsigned NOT NULL,
                `mode` enum('DISABLED','OPTIONAL','REQUIRED') NOT NULL DEFAULT 'DISABLED',
                `created` datetime NOT NULL,
                `created_by` int unsigned DEFAULT NULL,
                `modified` datetime NOT NULL,
                `modified_by` int unsigned DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `group_id` (`group_id`),
                KEY `created_by` (`created_by`),
                KEY `modified_by` (`modified_by`),
                CONSTRAINT `{{NAILS_DB_PREFIX}}mfa_group_policy_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `{{NAILS_DB_PREFIX}}user_group` (`id`) ON DELETE CASCADE,
                CONSTRAINT `{{NAILS_DB_PREFIX}}mfa_group_policy_ibfk_2` FOREIGN KEY (`created_by`) REFERENCES `{{NAILS_DB_PREFIX}}user` (`id`) ON DELETE SET NULL,
                CONSTRAINT `{{NAILS_DB_PREFIX}}mfa_group_policy_ibfk_3` FOREIGN KEY (`modified_by`) REFERENCES `{{NAILS_DB_PREFIX}}user` (`id`) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            EOT
        );

        $this->query(
            <<<'EOT'
            CREATE TABLE `{{NAILS_DB_PREFIX}}mfa_user_method` (
                `id` int unsigned NOT NULL AUTO_INCREMENT,
                `user_id` int unsigned NOT NULL,
                `driver` varchar(150) NOT NULL DEFAULT '',
                `is_default` tinyint(1) unsigned NOT NULL DEFAULT 0,
                `data` text DEFAULT NULL,
                `created` datetime NOT NULL,
                `created_by` int unsigned DEFAULT NULL,
                `modified` datetime NOT NULL,
                `modified_by` int unsigned DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `user_driver` (`user_id`, `driver`),
                KEY `user_id` (`user_id`),
                KEY `created_by` (`created_by`),
                KEY `modified_by` (`modified_by`),
                CONSTRAINT `{{NAILS_DB_PREFIX}}mfa_user_method_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `{{NAILS_DB_PREFIX}}user` (`id`) ON DELETE CASCADE,
                CONSTRAINT `{{NAILS_DB_PREFIX}}mfa_user_method_ibfk_2` FOREIGN KEY (`created_by`) REFERENCES `{{NAILS_DB_PREFIX}}user` (`id`) ON DELETE SET NULL,
                CONSTRAINT `{{NAILS_DB_PREFIX}}mfa_user_method_ibfk_3` FOREIGN KEY (`modified_by`) REFERENCES `{{NAILS_DB_PREFIX}}user` (`id`) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            EOT
        );
    }
}
