<?php

/**
 * The default MFA shell deliberately uses Nails' blank header. Applications can
 * replace it at application/modules/mfa/views/structure/header.php.
 */

/** @var \Nails\Common\Service\View $oView */
$oView = \Nails\Factory::service('View');
$oView->load(\Nails\Config::get('NAILS_COMMON_PATH') . 'views/structure/header/blank.php');
