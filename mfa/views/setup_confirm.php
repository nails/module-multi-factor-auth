<?php

use Nails\Common\Service\View;
use Nails\Factory;

/**
 * @var \Nails\MFA\Interfaces\Authentication\Driver $oDriver
 * @var \Nails\MFA\Resource\Token                   $oToken
 * @var object|null                                 $oPending
 * @var bool                                        $bCanGoBack
 * @var string                                      $sTrustedForLabel
 */

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
            <p>
                <small>
                    <?=htmlspecialchars($oDriver->getLabel())?> will become your default method. You can change your
                    default later from your two-factor authentication settings.
                </small>
            </p>
            <div class="form__actions form__actions--stacked">
                <button type="submit" name="action" value="setup_confirm" class="btn btn--block btn--primary">
                    Confirm and continue
                </button>
                <?php if ($bCanGoBack) { ?>
                    <button type="submit" name="action" value="setup_back" class="btn btn--block btn--secondary">
                        Choose another method
                    </button>
                <?php } ?>
                <button type="submit" name="action" value="setup_cancel" class="btn btn--block btn--link">
                    Cancel setup
                </button>
            </div>
            <?=form_close()?>
        </div>
    </div>
</div>
