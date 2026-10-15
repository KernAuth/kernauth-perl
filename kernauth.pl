use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use File::Temp qw(tempdir);
use JSON::PP ();
use MIME::Base64 qw(encode_base64 decode_base64);

our $API = "https://api.kernauth.com";
our $APP_ID = "__PUBLIC_APP_ID__";
our $KEY_ID = "__KEY_ID__";
our $PUBLIC_KEY = "__PUBLIC_KEY__";
our @FIELDS = qw(protocol_version entitlement_id application_id license_id status features device_id issued_at expires_at server_time nonce key_id);

package KernAuth;
use strict;
use warnings;

sub new {
  my ($class, $api, $app_id, $key_id, $public_key) = @_;
  return bless {
    api => $api // $main::API,
    app_id => $app_id // $main::APP_ID,
    key_id => $key_id // $main::KEY_ID,
    public_key => $public_key // $main::PUBLIC_KEY,
    success => 0,
    message => "",
    entitlement => undef,
  }, $class;
}

sub validate {
  my ($self, $license, $installation) = @_;
  return $self->call("validate", $license, $installation, "License is active");
}

sub call {
  my ($self, $mode, $license, $installation, $ok_message) = @_;
  my $entitlement = eval {
    main::request($mode, $license, $installation, $self->{api}, $self->{app_id}, $self->{key_id}, $self->{public_key});
  };
  if ($@) {
    $self->{success} = 0;
    $self->{message} = $@ || "request failed";
    $self->{message} =~ s/\s+\z//;
    $self->{entitlement} = undef;
    return 0;
  }
  $self->{success} = 1;
  $self->{message} = $ok_message;
  $self->{entitlement} = $entitlement;
  return 1;
}

package main;

my $json = JSON::PP->new->utf8->canonical->allow_nonref;
$json->escape_slash(0) if $json->can("escape_slash");

sub canonical_features {
  my ($value) = @_;
  $value = $json->decode($value) if !ref $value;
  return $json->encode(sort_json($value));
}

sub sort_json {
  my ($value) = @_;
  if (ref $value eq "HASH") {
    my %out;
    $out{$_} = sort_json($value->{$_}) for keys %$value;
    return \%out;
  }
  if (ref $value eq "ARRAY") {
    return [map { sort_json($_) } @$value];
  }
  return $value;
}

sub canonical {
  my ($entitlement) = @_;
  my @lines;
  for my $name (@FIELDS) {
    my $value = $name eq "features" ? canonical_features($entitlement->{$name}) : "$entitlement->{$name}";
    die "Invalid entitlement field\n" if $value =~ /[\r\n]/;
    push @lines, "$name=$value";
  }
  return join("\n", @lines) . "\n";
}

sub strict_b64 {
  my ($value) = @_;
  return undef if !defined $value || $value !~ m{\A[A-Za-z0-9+/]+={0,2}\z} || length($value) % 4 != 0;
  my $raw = eval { decode_base64($value) };
  return undef if !defined $raw;
  return $raw;
}

sub instant_ms {
  my ($text) = @_;
  return undef unless $text =~ /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z\z/;
  require Time::Local;
  my $seconds = Time::Local::timegm($6, $5, $4, $3, $2 - 1, $1);
  my $frac = $7 // "000";
  return $seconds * 1000 + int(substr($frac . "000", 0, 3));
}

sub verify_grant {
  my ($grant, $nonce, $app_id, $key_id, $public_key, $now_ms) = @_;
  $app_id //= $APP_ID;
  $key_id //= $KEY_ID;
  $public_key //= $PUBLIC_KEY;
  $now_ms //= int(time() * 1000);
  my $ok = eval {
    my $ent = $grant->{entitlement};
    my $expiry = instant_ms($ent->{expires_at});
    return 0 if $ent->{protocol_version} != 1 || $ent->{nonce} ne $nonce || $ent->{application_id} ne $app_id
      || $ent->{key_id} ne $key_id || $ent->{status} ne "active" || !defined $expiry || $expiry <= $now_ms;
    my $raw = strict_b64($public_key);
    my $signature = strict_b64($grant->{signature});
    return 0 if !defined $raw || length($raw) != 32 || !defined $signature || length($signature) != 64;
    return ed25519_verify(canonical($ent), $signature, $raw);
  };
  return $ok ? 1 : 0;
}

sub ed25519_verify {
  my ($message, $signature, $public) = @_;
  my $dir = tempdir(CLEANUP => 1);
  my $der = pack("H*", "302a300506032b6570032100") . $public;
  open my $pem, ">", "$dir/pub.pem" or return 0;
  print {$pem} "-----BEGIN PUBLIC KEY-----\n" . encode_base64($der, "") . "\n-----END PUBLIC KEY-----\n";
  close $pem;
  open my $msg, ">", "$dir/msg" or return 0;
  binmode $msg;
  print {$msg} $message;
  close $msg;
  open my $sig, ">", "$dir/sig" or return 0;
  binmode $sig;
  print {$sig} $signature;
  close $sig;
  my $command = "openssl pkeyutl -verify -pubin -inkey '$dir/pub.pem' -rawin -in '$dir/msg' -sigfile '$dir/sig' >/dev/null 2>&1";
  return system($command) == 0 ? 1 : 0;
}

sub request {
  my ($mode, $license, $installation, $api, $app_id, $key_id, $public_key) = @_;
  open my $random, "<", "/dev/urandom" or die "urandom\n";
  read $random, my $bytes, 24 or die "urandom\n";
  close $random;
  my $nonce = encode_base64($bytes, "");
  $nonce =~ tr{+/}{-_};
  $nonce =~ s/=+\z//;
  my $fingerprint = sha256_hex("kernauth-device-v1:$installation");
  my $body = $json->encode({
    protocol_version => 1, public_app_id => $app_id, client_version => "1.0.0", license_key => $license,
    fingerprint_version => 1, device_fingerprint => $fingerprint, installation_id => $installation, nonce => $nonce,
  });
  my $dir = tempdir(CLEANUP => 1);
  open my $out, ">", "$dir/body" or die $!;
  print {$out} $body;
  close $out;
  open my $response, "-|", "curl", "-sS", "-w", "\n%{http_code}", "-X", "POST", "-H", "content-type: application/json",
    "--data-binary", "\@$dir/body", "$api/v1/client/$mode" or die "curl\n";
  local $/;
  my $raw = <$response>;
  close $response;
  die "$mode failed\n" if $? != 0 || !defined $raw;
  $raw =~ s/\n(\d{3})\z// or die "$mode failed\n";
  my $status = $1;
  die "$mode failed ($status)\n" if $status !~ /\A2/;
  my $grant = JSON::PP->new->utf8(0)->decode($raw);
  die "Invalid or expired signed entitlement\n" unless verify_grant($grant, $nonce, $app_id, $key_id, $public_key);
  return $grant->{entitlement};
}

sub license_key {
  my $env = $ENV{KERN_LICENSE_KEY} // "";
  $env =~ s/^\s+|\s+$//g;
  return $env if $env ne "";
  print "Enter license: " if -t STDIN;
  my $line = <STDIN> // "";
  $line =~ s/^\s+|\s+$//g;
  return $line;
}

sub installation_id {
  my $env = $ENV{KERN_INSTALLATION_ID} // "";
  $env =~ s/^\s+|\s+$//g;
  return $env if $env ne "";
  if (open my $in, "<", "kernauth-install") {
    local $/;
    my $saved = <$in> // "";
    close $in;
    $saved =~ s/^\s+|\s+$//g;
    return $saved if $saved ne "";
  }
  open my $random, "<", "/dev/urandom" or die "urandom\n";
  read $random, my $bytes, 16 or die "urandom\n";
  close $random;
  my $saved = unpack("H*", $bytes);
  open my $out, ">", "kernauth-install" or die "Could not save the installation id\n";
  print {$out} "$saved\n";
  close $out;
  return $saved;
}

unless (caller) {
  my $app = KernAuth->new();
  die $app->{message} . "\n" unless $app->validate(license_key(), installation_id());
  my $ent = $app->{entitlement};
  print "Status: $ent->{status}\n";
  print "Features: ", canonical_features($ent->{features}), "\n";
  print "License: $ent->{license_id}\n";
  print "Check expires: $ent->{expires_at}\n";
}

1;
