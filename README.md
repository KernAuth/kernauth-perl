# KernAuth Perl example

Paste the public app ID from Developers into `main.pl`. Perl 5.14 or newer. The core has no HTTPS client, so the library uses curl.

## Start

```perl
my $app = KernAuth->new("https://api.kernauth.com", "__PUBLIC_APP_ID__");
```

Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program checks that the key is valid and prints when it expires. It does not save a computer.

## Run

```
perl test_kernauth.pl
perl main.pl
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
