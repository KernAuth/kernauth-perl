# KernAuth Perl example

Example for Perl 5.14 or newer. Perl's core has no HTTPS client, so this file uses `curl` for the request and the `openssl` command for the signature. This file calls validate and checks the Ed25519 signature.

## Add it

Paste the public app ID, key ID, and public key from Developers over the placeholders in `kernauth.pl`.

```
perl test_kernauth.pl
```

Run from the repository root so the test can read `vectors.json`. Run the example with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

## Instance

```perl
my $app = KernAuth->new(
  "https://api.kernauth.com",
  "__PUBLIC_APP_ID__",
  "__KEY_ID__",
  "__PUBLIC_KEY__",
);
```

## Validate

```perl
die $app->{message} unless $app->validate($license, $installation);
```

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io
