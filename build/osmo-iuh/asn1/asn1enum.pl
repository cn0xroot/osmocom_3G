#!/usr/bin/perl -w
use strict;

# small script to extract the constants from
# {HNBAP,RUA,RANAP}-Constants.asn and print them in an ASN.1 format that
# will trigger asn1c to generate associated enums in C.
#
# Usage: ./asn1enum.pl < HNBAP-Constants.asn

my $l;
my %h;

while ($l = <STDIN>) {
	chomp($l);
	if ($l =~ /^(\S+)\s+(\S+)\s+::=\s+(\d+)/) {
		$h{$2}{$3} = $1;
	}
}

foreach my $k (keys %h) {
	if ($k eq 'INTEGER') {
		next;
	}
	printf("%s ::= INTEGER {\n", $k);
	foreach my $r (sort { $a <=> $b } keys $h{$k}) {
		printf("\t%s(%d),\n", $h{$k}{$r}, $r);
	}
	printf("}\n");
}
