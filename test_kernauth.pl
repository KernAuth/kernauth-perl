use strict;
use warnings;
use FindBin;
use lib $FindBin::Bin;
use KernAuth;

my $body = KernAuth::check_body("pub_harbor_desktop", "KERN-ABCD-EFGH-IJKL-MNOP");
die "body\n" if $body->{protocol_version} != 1 || $body->{public_app_id} ne "pub_harbor_desktop"
  || $body->{client_version} ne "1.0.0" || $body->{license_key} ne "KERN-ABCD-EFGH-IJKL-MNOP";
die "message\n" if KernAuth::api_message({ error => { message => "Update required" } }, "no") ne "Update required";
die "fallback\n" if KernAuth::api_message({}, "no") ne "no";
print "Perl check passed\n";
