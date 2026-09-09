# MFA Module for Nails

![license](https://img.shields.io/badge/license-MIT-green.svg)
[![tests](https://github.com/nails/module-multi-factor-auth/actions/workflows/build_and_test.yml/badge.svg )](https://github.com/nails/module-multi-factor-auth/actions)

This is the MFA module for Nails, it provides two factor authentication support for `module-auth` powered by drivers.

## Configuration

Set these as config properties (e.g. in `config/app.php`):

- `MFA_TRUSTED_DEVICE_TTL` — how long, in seconds, a device stays trusted when the user opts to not be asked again. Defaults to 14 days.
- `MFA_TRUST_SURVIVES_LOGOUT` — whether a trusted device stays trusted after the user signs out. Defaults to `false`, i.e. signing out ends that device's trust.

The service's constants can also be overridden by extending it at app level, most usefully `TOKEN_TTL` (how long a challenge lasts), `MAX_VERIFICATION_ATTEMPTS` (incorrect codes allowed per challenge), `MAX_RESENDS_PER_TOKEN` (replacement codes a user can request per challenge), and `MAX_TOKEN_MINTS_PER_HOUR` (new challenges issued per user per hour).

## Views

MFA pages use Nails' blank header and footer by default. Applications can inject their own page shell by providing `application/modules/mfa/views/structure/header.php` and `application/modules/mfa/views/structure/footer.php`; individual MFA views can be overridden in the same module view directory.

## Console utilities

Run commands through the Nails console:

```bash
php vendor/nails/module-console/console.php mfa:config
```

Available MFA commands:

- `mfa:config` — show installed/enabled drivers and group policies.
- `mfa:driver:enable --driver=<package>` — enable an installed driver.
- `mfa:driver:disable --driver=<package>` — disable a driver while retaining user enrollments.
- `mfa:driver:setting --driver=<package> [--key=<key> [--value=<value>]]` — inspect or update driver app settings. Use `--json` for structured values.
- `mfa:group:policy --group=<id-or-slug> [--mode=DISABLED|OPTIONAL|REQUIRED]` — inspect or update a group policy.
- `mfa:user:status --user=<id-email-or-username>` — show a user's effective policy and enrolled methods.
- `mfa:user:method:add --user=<user> --driver=<package> [--default]` — enroll a non-interactive driver such as Email.
- `mfa:user:method:remove --user=<user> --driver=<package>` — remove an enrollment.
- `mfa:user:method:default --user=<user> --driver=<package>` — change the user's default method.

Omit `--driver`, `--user`, or `--group` in an interactive terminal to be prompted. `--force` and `--no-interaction` skip prompts and require those options to be set. Mutating commands request confirmation. Pass `--force` for unattended execution. Drivers which hold a user secret, such as Authenticator, must be enrolled interactively so the secret and QR code are delivered directly to the user.
