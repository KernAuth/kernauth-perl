package KernAuth;
use strict;
use warnings;
use JSON::PP;

sub check_body {
  my ($app_id, $license_key) = @_;
  return {
    protocol_version => 1,
    public_app_id => $app_id,
    client_version => "1.0.0",
    license_key => $license_key,
  };
}

sub api_message {
  my ($payload, $fallback) = @_;
  my $message = ref($payload) eq "HASH" && ref($payload->{error}) eq "HASH" ? $payload->{error}{message} : undef;
  return defined $message && $message ne "" ? $message : $fallback;
}

sub new {
  my ($class, $api, $app_id) = @_;
  return bless { api => $api, app_id => $app_id, message => "", expires_at => undef }, $class;
}

sub check {
  my ($self, $license_key) = @_;
  my $json = JSON::PP->new->utf8->canonical;
  my $body = $json->encode(check_body($self->{app_id}, $license_key));
  my $command = "curl -sS -m 10 -w '\\n%{http_code}' -H 'content-type: application/json' -d " . quotemeta_shell($body) . " " . quotemeta_shell("$self->{api}/v1/client/check");
  my $raw = `$command`;
  my ($payload_raw, $status) = $raw =~ /^(.*)\n(\d{3})\s*$/s;
  my $payload = eval { $json->decode($payload_raw // "") };
  if (($status // 0) != 200 || ref($payload) ne "HASH" || !$payload->{valid}) {
    $self->{message} = api_message($payload, "check failed (" . ($status // 0) . ")");
    $self->{expires_at} = undef;
    return 0;
  }
  $self->{message} = "License is active";
  $self->{expires_at} = ref($payload->{expires_at}) ? undef : $payload->{expires_at};
  $self->{expires_at} = undef if defined $self->{expires_at} && $self->{expires_at} eq "";
  return 1;
}

sub quotemeta_shell {
  my ($value) = @_;
  $value =~ s/'/'\\''/g;
  return "'$value'";
}

1;
