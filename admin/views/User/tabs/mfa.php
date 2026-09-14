<?php

/**
 * @var \Nails\Auth\Resource\User $oUser
 * @var string $sGroupMode
 * @var array<string, string> $aModes
 * @var \Nails\MFA\Resource\UserMethod[] $aMethods
 * @var array<string, string> $aDriverLabels
 * @var bool $bIsSelf
 * @var string|null $sManageUrl
 */

$fnLabel = static fn(string $sDriver): string => $aDriverLabels[$sDriver] ?? $sDriver;

if ($bIsSelf && $sManageUrl) {
    ?>
    <div class="alert alert-info">
        Use the self-service page to add, remove, or choose your default verification method.
        <a href="<?=htmlspecialchars($sManageUrl, ENT_QUOTES)?>" class="btn btn-sm btn-primary">
            Manage my verification methods
        </a>
    </div>
    <?php
}

echo form_field([
    'key'      => 'mfa_group_policy',
    'label'    => 'Group Policy',
    'default'  => $aModes[$sGroupMode] ?? $sGroupMode,
    'readonly' => true,
    'info'     => 'Inherited from the user\'s group; change it on the group itself.',
]);

if (empty($aMethods)) {

    echo form_field([
        'key'      => 'mfa_methods',
        'label'    => 'Enrolled Methods',
        'default'  => 'None',
        'readonly' => true,
        'info'     => implode('', [
            '<div class="alert alert-warning" style="margin:0;">',
            'This user must enrol a method themselves; secrets and QR codes are never shown here.',
            '</div>',
        ]),
    ]);

} else {

    echo form_field_radio([
        'key'     => 'mfa_default_driver',
        'label'   => 'Default Method',
        'options' => array_values(array_map(
            static fn($oMethod) => [
                'value'    => (string) $oMethod->driver,
                'label'    => $fnLabel((string) $oMethod->driver),
                'selected' => (bool) $oMethod->is_default,
            ],
            $aMethods
        )),
        'info'    => 'The method the user is challenged with by default.',
    ]);

    echo form_field_checkbox([
        'key'     => 'mfa_reset_driver[]',
        'label'   => 'Reset Methods',
        'options' => array_values(array_map(
            static fn($oMethod) => [
                'value' => (string) $oMethod->driver,
                'label' => $fnLabel((string) $oMethod->driver),
            ],
            $aMethods
        )),
        'info'    => implode('', [
            '<div class="alert alert-warning" style="margin:0;">',
            'Resetting removes the enrolment; the user must set the method up again. ',
            'Secrets and QR codes are never shown here.',
            '</div>',
        ]),
    ]);
}
