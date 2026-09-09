<?php

/**
 * The default MFA shell deliberately uses Nails' blank footer. Applications can
 * replace it at application/modules/mfa/views/structure/footer.php.
 */

/** @var \Nails\Common\Service\View $oView */
$oView = \Nails\Factory::service('View');
$oView->load(\Nails\Config::get('NAILS_COMMON_PATH') . 'views/structure/footer/blank.php');
