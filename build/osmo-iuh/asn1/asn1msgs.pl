#!/usr/bin/perl -w
#use strict;

# small script to extract the types used in elementary procedures
# {HNBAP,RUA,RANAP}-PDU-Descriptions.asn and print them in an ASN.1
# format that will trigger asn1c to generate associated structures
#
# Usage: ./asn1enum.pl < HNBAP-PDU-Descriptions.asn

my $l;
my @a;

while ($l = <STDIN>) {
	chomp($l);
	if ($l =~ /^\s*(\S+\s*\S+)\s+(\S+)\s*$/) {
		if ($1 eq 'INITIATING MESSAGE' ||
		    $1 eq 'SUCCESSFUL OUTCOME' ||
		    $1 eq 'UNSUCCESSFUL OUTCOME' ||
	    	    $1 eq 'OUTCOME') {
			push(@a, $2);
		}
	}
}

foreach my $k (@a) {
	my $lk = $k;
	my $firstchar = substr($lk, 0, 1);
	if ($firstchar =~ /^[A-Z]/) {
		substr($lk, 0, 1, lc($firstchar));
	}
	printf("%s ::= SEQUENCE {\n", $k);
	printf("    %s-ies SEQUENCE (SIZE (0..maxProtocolIEs)) OF IE,\n", $lk);
	printf("    ...\n");
	printf("}\n\n");
}
