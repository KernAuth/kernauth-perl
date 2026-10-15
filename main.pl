use strict;
use warnings;
use FindBin;
use lib $FindBin::Bin;
use KernAuth;

sub license_key {
  my $from_env = $ENV{KERN_LICENSE_KEY} // "";
  $from_env =~ s/^\s+|\s+$//g;
  return $from_env if $from_env ne "";
  print "Enter license: " if -t STDIN;
  my $line = <STDIN> // "";
  $line =~ s/^\s+|\s+$//g;
  return $line;
}

my $app = KernAuth->new("https://api.kernauth.com", "__PUBLIC_APP_ID__");
unless ($app->check(license_key())) {
  print $app->{message}, "\n";
  exit 1;
}
print "Status: active\n";
print defined $app->{expires_at} ? "Expires: $app->{expires_at}\n" : "Expires: Lifetime\n";
