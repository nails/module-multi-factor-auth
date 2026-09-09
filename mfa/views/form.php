<?php

use Nails\Common\Service\View;
use Nails\Factory;

/**
 * @var \Nails\MFA\Interfaces\Authentication\Driver $oDriver
 * @var \Nails\MFA\Resource\Token                   $oToken
 * @var \Nails\MFA\Interfaces\Authentication\Driver[] $aOtherMethods
 * @var bool                                        $bIsSetup
 * @var bool                                        $bCanGoBack
 * @var string                                      $sTrustedForLabel
 */

$aOtherMethods = $aOtherMethods ?? [];

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
                <?=form_input('code', set_value('code'), 'id="input-code" autocomplete="one-time-code" inputmode="numeric" class="form__control"')?>
            </div>
            <div class="form__group form__group--checkbox-compact">
                <?=form_checkbox('remember', true, set_checkbox('remember'), 'id="input-remember"')?>
                <label for="input-remember">
                    Trust this device for <?=htmlspecialchars($sTrustedForLabel)?>
                </label>
            </div>
            <?php if ($bIsSetup) { ?>
                <p>
                    <small>
                        <?=htmlspecialchars($oDriver->getLabel())?> will become your default method. You can change your
                        default later from your two-factor authentication settings.
                    </small>
                </p>
            <?php } ?>
            <div class="form__actions form__actions--stacked">
                <button type="submit" name="action" value="verify" class="btn btn--block btn--primary" id="mfa-btn-verify">
                    Verify
                </button>
                <?php

                if ($oDriver->canTryAgain()) {
                    ?>
                    <button type="submit" name="action" value="resend" class="btn btn--block btn--secondary" id="mfa-btn-retry">
                        Request another verification code
                    </button>
                    <?php
                }

                ?>
                <?php if ($bIsSetup && $bCanGoBack) { ?>
                    <button type="submit" name="action" value="setup_back" class="btn btn--block btn--secondary">
                        Choose another method
                    </button>
                <?php } ?>
            </div>
            <?=form_close()?>
            <?php

            if (!empty($aOtherMethods)) {
                ?>
                <div class="form__actions form__actions--stacked">
                    <?php

                    foreach ($aOtherMethods as $oOther) {
                        echo form_open(null, 'class="form"');
                        ?>
                        <input type="hidden" name="driver" value="<?=htmlspecialchars((string) $oOther->getSlug())?>">
                        <button type="submit" name="action" value="switch" class="btn btn--block btn--secondary">
                            Use <?=htmlspecialchars($oOther->getLabel())?>
                        </button>
                        <?php
                        echo form_close();
                    }

                    ?>
                </div>
                <?php
            }

            ?>
            <div id="mfa-submitting" style="display: none" class="form__group text-center">
                Please wait...
            </div>
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
