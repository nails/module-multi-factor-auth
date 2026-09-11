<?php

use Nails\Common\Service\View;
use Nails\Factory;
use Nails\MFA\Interfaces\Authentication\Driver\Interactive;

/**
 * @var \Nails\MFA\Interfaces\Authentication\Driver $oDriver
 * @var \Nails\MFA\Resource\Token                   $oToken
 * @var object|null                                 $oPending
 * @var bool                                        $bCanChooseAnother
 * @var string                                      $sTrustedForLabel
 */

$bInteractive = $oDriver instanceof Interactive;
$bHideCode    = $bInteractive && $oDriver->hidesCodeInput();

/** @var View $oView */
$oView = Factory::service('View');

?>
<div class="nails-auth mfa center-screen">
    <div class="panel">
        <div class="panel__header">
            <h1 class="panel__title text-center">
                Set up <?=htmlspecialchars($oDriver->getLabel())?>
            </h1>
        </div>
        <div class="panel__body">
            <?php

            echo form_open(null, 'id="mfa-form" class="form"');
            $oView->load('auth/_components/alerts');

            if ($bInteractive) {

                //  See form.php: the driver JS locates this via [name="action"] and
                //  sets it before a programmatic form.submit(), which carries no
                //  button's name/value on its own.
                ?>
                <input type="hidden" name="action" value="">
                <?php

                $oUser = $oToken->user();
                if ($oUser !== null) {
                    echo $oDriver->getSetupMarkup($oUser, $oPending instanceof \stdClass ? $oPending : (object) (array) $oPending);
                }

            } else {

                if (!empty($oPending->qr_svg)) {
                    ?>
                    <div class="text-center">
                        <?=$oPending->qr_svg?>
                    </div>
                    <?php
                }

                if (!empty($oPending->secret)) {
                    ?>
                    <p class="text-center">
                        Secret: <code><?=htmlspecialchars((string) $oPending->secret)?></code>
                    </p>
                    <?php
                }

                ?>
                <p>Scan the QR code with your authenticator app, then enter the code it shows to confirm setup.</p>
                <?php
            }

            if ($bHideCode) {
                ?>
                <input type="hidden" name="code" id="input-code" value="<?=htmlspecialchars((string) set_value('code'))?>">
                <?php
            } else {
                ?>
                <div class="form__group">
                    <label class="form__label" for="input-code">Code</label>
                    <?=form_input('code', set_value('code'), 'id="input-code" autocomplete="one-time-code" inputmode="numeric" class="form__control"')?>
                </div>
                <?php
            }

            ?>
            <div class="form__group form__group--checkbox-compact">
                <?=form_checkbox('remember', true, set_checkbox('remember'), 'id="input-remember"')?>
                <label for="input-remember">
                    Trust this device for <?=htmlspecialchars($sTrustedForLabel)?>
                </label>
            </div>
            <p>
                <small>
                    <?=htmlspecialchars($oDriver->getLabel())?> will become your default method. You can change your
                    default later from your two-factor authentication settings.
                </small>
            </p>
            <div class="form__actions form__actions--stacked">
                <?php if (!$bHideCode) { ?>
                    <button type="submit" name="action" value="setup_confirm" class="btn btn--block btn--primary">
                        Confirm and continue
                    </button>
                <?php } ?>
            </div>
            <?=form_close()?>
            <?php $oView->load('mfa/_components/challenge_actions') ?>
        </div>
    </div>
</div>
