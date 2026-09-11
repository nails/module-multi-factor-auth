<?php

use Nails\Common\Service\View;
use Nails\Factory;

/**
 * @var \Nails\MFA\Resource\Token $oToken
 * @var \Nails\MFA\Interfaces\Authentication\Driver[] $aDrivers
 */

/** @var View $oView */
$oView = Factory::service('View');

?>
<div class="nails-auth mfa center-screen">
    <h1 class="text-center">
        Set up two-factor authentication
    </h1>
    <p class="text-center">
        Choose how you would like to verify your identity when you sign in.
    </p>
    <?php

    $oView->load('auth/_components/alerts');

    foreach ($aDrivers as $oDriver) {
        echo form_open(null, 'class="form"');
        ?>
        <div class="panel">
            <div class="panel__body">
                <h2><?=htmlspecialchars($oDriver->getLabel())?></h2>
                <p><?=htmlspecialchars($oDriver->getSetupDescription())?></p>
            </div>
            <div class="panel__footer">
                <input type="hidden" name="driver" value="<?=htmlspecialchars((string) $oDriver->getSlug())?>">
                <button type="submit" name="action" value="setup_choose" class="btn btn--block btn--primary">
                    Use <?=htmlspecialchars($oDriver->getLabel())?>
                </button>
            </div>
        </div>
        <?php
        echo form_close();
    }

    if (empty($aDrivers)) {
        ?>
        <div class="panel">
            <div class="panel__body">
                <p>No verification methods are available. Please contact support.</p>
            </div>
        </div>
        <?php
    }

    $oView->load('mfa/_components/challenge_actions');

    ?>
</div>
