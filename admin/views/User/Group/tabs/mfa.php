<?php

/**
 * @var \Nails\Auth\Resource\User\Group $oGroup
 * @var array<string, string> $aModes
 * @var string $sPolicyMode
 */

echo form_field_dropdown([
    'key'     => 'mfa_group_policy',
    'label'   => 'Policy',
    'class'   => 'select2',
    'default' => $sPolicyMode,
    'options' => $aModes,
    'info'    => implode('', [
        '<div class="alert alert-info" style="margin:0;">',
        '<strong>Disabled</strong> skips MFA for this group.',
        '<br />' . '<strong>Optional</strong> challenges users once they enrol a method.',
        '<br />' . '<strong>Required</strong> always challenges users, and forces setup on their next login if nothing is enrolled.',
        '</div>',
    ]),
]);
