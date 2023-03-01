<?php
/**
 * This config file defines all the email types for this app
 * Add new emails using the Nails CLI tool: nails make:email
 * Generated: 2022-08-22 14:07:29
 **/

$config['email_types'] = [
    (object) [
        'slug'            => 'mfa_email_code',
        'name'            => 'MFA: Email code',
        'description'     => 'Email sent to user with thier login code when using the email MFA driver',
        'template_header' => '',
        'template_body'   => 'mfa/email/code',
        'template_footer' => '',
        'default_subject' => 'Your login verification code',
        'is_hidden'       => false,
        'is_editable'     => true,
        'can_unsubscribe' => false,
        'factory'         => 'app/module-multi-factor-auth::EmailCode',
    ],
];
