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
        <?=form_open(null, 'id="mfa-form"')?>
        <div class="panel__body">
            <?php

            $oView->load('auth/_components/alerts');

            ?>
            <div class="form__group <?=form_error('code') ? 'has-error' : ''?>">
                <label for="input-code">Code</label>
                <?=form_input('code', set_value('code'), 'id="input-code" autocomplete="one-time-code"')?>
            </div>
            <div class="form__group <?=form_error('remember') ? 'has-error' : ''?>">
                <?=form_checkbox('remember', true, set_checkbox('remember'), 'id="input-remember"')?>
                <label for="input-remember">Don't ask again on this device</label>
            </div>
            <p>
                <button type="submit" name="action" value="verify" class="btn btn--block btn--primary" id="mfa-btn-verify">
                    Verify
                </button>
            </p>
            <?php

            if ($oDriver->canTryAgain()) {
                ?>
                <p>
                    <button type="submit" name="action" value="restart" class="btn btn--block btn--secondary" id="mfa-btn-retry">
                        Request another verification code
                    </button>
                </p>
                <?php
            }

            ?>
            <div id="mfa-submitting" style="display: none" class="form__group text-center">
                Please wait...
            </div>
        </div>
        <?=form_close()?>
    </div>
</div>
<script>

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

</script>
