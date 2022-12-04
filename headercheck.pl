#!/usr/bin/perl

# This script checks for the presence of the various HTTP security headers
# for a list of websites, specified in the file "websites.txt".
#
# Usage:
# perl http_security_headers_check.pl

use LWP::UserAgent;

open(FILE, "<websites.txt");
while (my $line = <FILE>) {
    chomp $line;
    my $ua = LWP::UserAgent->new;
    $ua->timeout(5);
    my $req = HTTP::Request->new(GET => $line); 
    my $resp = $ua->request($req);

    my $x_frame_opt = $resp->header('X-Frame-Options');
    my $x_xss_prot = $resp->header('X-XSS-Protection');
    my $x_content_type = $resp->header('X-Content-Type-Options');
    my $strict_trans = $resp->header('Strict-Transport-Security');
    my $content_sec = $resp->header('Content-Security-Policy');

    print "Checking $line\n";

    if ($x_frame_opt) {
        print "  X-Frame-Options present\n";
    } else {
        print "  X-Frame-Options not present\n";
    }

    if ($x_xss_prot) {
        print "  X-XSS-Protection present\n";
    } else {
        print "  X-XSS-Protection not present\n";
    }

    if ($x_content_type) {
        print "  X-Content-Type-Options present\n";
    } else {
        print "  X-Content-Type-Options not present\n";
    }

    if ($strict_trans) {
        print "  Strict-Transport-Security present\n";
    } else {
        print "  Strict-Transport-Security not present\n";
    }

    if ($content_sec) {
        print "  Content-Security-Policy present\n";
    } else {
        print "  Content-Security-Policy not present\n";
    }
}

close(FILE);