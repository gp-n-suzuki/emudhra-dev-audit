use strict;
use warnings;
use JSON::PP;
sub emit { print 'EMUDHRA_JSON:' . encode_json($_[0]) . "\n"; }
if (($ARGV[0] || '') eq 'meta') {
    my $ca = eval { require Mozilla::CA; $Mozilla::CA::VERSION } || '';
    my $lwp = eval { require LWP::UserAgent; $LWP::UserAgent::VERSION } || '';
    emit({state=>'meta',data=>{version=>sprintf('%vd',$^V),mozilla_ca=>"$ca",lwp=>"$lwp"}});
    exit;
}
if (($ARGV[0] || '') eq 'lwp') {
    if (!eval { require LWP::UserAgent; require HTTP::Request; require IO::Socket::SSL; 1 }) {
        emit({state=>'skipped',detail=>'LWP::UserAgent / IO::Socket::SSLを利用できません。',optional_missing=>JSON::PP::true}); exit;
    }
    if (($ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} || '') eq '0') {
        emit({state=>'skipped',detail=>'LWPのホスト名検証が無効のため通信を見送ります。'}); exit;
    }
    my $client = LWP::UserAgent->new(timeout=>0+$ARGV[2], max_redirect=>0);
    $client->env_proxy;
    my $result = eval { $client->simple_request(HTTP::Request->new('HEAD', $ARGV[1])) };
    if (!$result) { emit({state=>'error',detail=>"$@"}); }
    elsif (($result->header('Client-Warning') || '') =~ /Internal response/i) {
        emit({state=>'error',detail=>$result->status_line . ' ' . $result->decoded_content});
    } else { emit({state=>'accepted',detail=>'HTTP '.$result->code}); }
    exit;
}
if (!eval { require HTTP::Tiny; require IO::Socket::SSL; 1 }) {
    emit({state=>'skipped',detail=>'HTTP::Tiny / IO::Socket::SSLを利用できません。'}); exit;
}
my $client = HTTP::Tiny->new(verify_SSL=>1, max_redirect=>0, timeout=>0+$ARGV[2], max_size=>16384);
my $result = eval { $client->request('HEAD', $ARGV[1]) };
if (!$result) { emit({state=>'error',detail=>"$@"}); }
elsif ($result->{status} == 599) { emit({state=>'error',detail=>$result->{content} || $result->{reason}}); }
else { emit({state=>'accepted',detail=>'HTTP '.$result->{status}}); }
