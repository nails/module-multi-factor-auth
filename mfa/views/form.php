<?php

use Nails\Common\Service\View;
use Nails\Factory;

/**
 * @var \Nails\MFA\Interfaces\Authentication\Driver $oDriver
 * @var \Nails\MFA\Resource\Token                   $oToken
 */

/** @var View $oView */
$oView = Factory::service('View');

?>
<div class="nails-auth mfa u-center-screen">
    <div class="panel">
        <h1 class="panel__header text-center">
            Two Factor Authentication
        </h1>
        <?=form_open()?>
        <div class="panel__body">
            <?php

            $oView->load('auth/_components/alerts');

            $sFieldKey = 'code';

            ?>
            <div class="form__group <?=form_error('code') ? 'has-error' : ''?>">
                <label for="input-<?='code'?>">Code</label>
                <?=form_input('code', set_value('code'))?>
            </div>
            <p>
                <button type="submit" name="action" value="verify" class="btn btn--block btn--primary">
                    Verify
                </button>
            </p>
            <?php

            if ($oDriver->canTryAgain()) {
                ?>
                <p>
                    <button type="submit" name="action" value="restart" class="btn btn--block btn--secondary">
                        Request another verification code
                    </button>
                </p>
                <?php
            }

            ?>
        </div>
        <?=form_close()?>
    </div>
</div>
