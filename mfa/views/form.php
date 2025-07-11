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
<div class="nails-auth mfa center-screen">
    <div class="panel">
        <div class="panel__header">
            <h1 class="panel__title text-center">
                Two Factor Authentication
            </h1>
        </div>
        <div class="panel__body">
            <?php

            echo form_open(null, 'id="mfa-form" class="form"');
            $oView->load('auth/_components/alerts');

            ?>
            <div class="form__group">
                <label class="form__label" for="input-code">Code</label>
                <?=form_input('code', set_value('code'), 'id="input-code" autocomplete="one-time-code" class="form_control"')?>
            </div>
            <div class="form__group form__group--checkbox-compact">
                <?=form_checkbox('remember', true, set_checkbox('remember'), 'id="input-remember"')?>
                <label for="input-remember">Don't ask again on this device</label>
            </div>
            <div class="form__actions">
                <button type="submit" name="action" value="verify" class="btn btn--block btn--primary" id="mfa-btn-verify">
                    Verify
                </button>
                <?php

                if ($oDriver->canTryAgain()) {
                    ?>
                    <button type="submit" name="action" value="restart" class="btn btn--block btn--secondary" id="mfa-btn-retry">
                        Request another verification code
                    </button>
                    <?php
                }

                ?>
            </div>
            <div id="mfa-submitting" style="display: none" class="form__group text-center">
                Please wait...
            </div>
            <?=form_close()?>
        </div>
    </div>
</div>
<?=scriptOpen()?>

var form = document.getElementById('mfa-form');
var btnVerify = document.getElementById('mfa-btn-verify');
var btnRetry = document.getElementById('mfa-btn-retry');
var submitting = document.getElementById('mfa-submitting');

form.addEventListener('submit', function() {
    btnVerify.style.display = 'none';
    if (btnRetry) {
        btnRetry.style.display = 'none';
    }
    submitting.style.display = 'block';
});

<?=scriptClose()?>
