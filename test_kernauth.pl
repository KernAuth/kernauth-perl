use strict;
use warnings;
use JSON::PP ();
require "./kernauth.pl";

my $parser = JSON::PP->new->utf8;
my $fixture = $parser->decode(do {
  local $/;
  open my $handle, "<", "vectors.json" or die $!;
  <$handle>;
});
my $now = main::instant_ms("2026-01-01T00:01:00.000Z");
for my $vector (@{$fixture->{vectors}}) {
  my $ent = $vector->{fields};
  my $grant = { entitlement => $ent, signature => $vector->{signature} };
  my $canonical = main::canonical($ent);
  die "$vector->{name} canonical\n" if $canonical ne $vector->{canonical};
  my $args = [$ent->{nonce}, $ent->{application_id}, $ent->{key_id}, $vector->{public_key}, $now];
  die "$vector->{name}\n" unless main::verify_grant($grant, @$args)
    && !main::verify_grant($grant, "wrong", $ent->{application_id}, $ent->{key_id}, $vector->{public_key}, $now)
    && !main::verify_grant($grant, $ent->{nonce}, "pub_other_app", $ent->{key_id}, $vector->{public_key}, $now)
    && !main::verify_grant($grant, $ent->{nonce}, $ent->{application_id}, "wrong-key", $vector->{public_key}, $now)
    && !main::verify_grant({ entitlement => $ent, signature => $vector->{signature} . "AA" }, @$args)
    && !main::verify_grant($grant, $ent->{nonce}, $ent->{application_id}, $ent->{key_id}, $vector->{public_key}, main::instant_ms($ent->{expires_at}))
    && !main::verify_grant({ entitlement => { %$ent, device_id => "other" }, signature => $vector->{signature} }, @$args)
    && !main::verify_grant({ entitlement => { %$ent, status => "revoked" }, signature => $vector->{signature} }, @$args);
}
print "Perl vectors passed\n";
