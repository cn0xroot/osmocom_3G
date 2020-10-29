#!/usr/bin/perl
#
use strict;
use DBI;
my $dbh = DBI->connect("dbi:SQLite:dbname=hlr.db","","");

my $sth_subscr_base = $dbh->prepare("INSERT INTO subscriber (imsi, msisdn) VALUES (?, ?)");
my $sth_subscr_get_id = $dbh->prepare("SELECT * FROM subscriber WHERE imsi = ?");
my $sth_auc_3g = $dbh->prepare("INSERT INTO auc_3g (subscriber_id, algo_id_3g, k, op, sqn) VALUES (?, ?, ?, ?, ?)");
my $sth_auc_2g = $dbh->prepare("INSERT INTO auc_2g (subscriber_id, algo_id_2g, ki) VALUES (?, ?, ?)");

sub create_subscr_base($)
{
	my ($imsi) = @_;
	my $suffix = substr($imsi, 5);

	my $msisdn = "49" . $suffix;

	return $sth_subscr_base->execute($imsi, $msisdn);
}

sub create_auc_2g($)
{
	my ($id) = @_;

	my $ki = "000102030405060708090a0b0c0d0e0f";

	$sth_auc_2g->execute($id, 1, $ki);
}

sub create_auc_3g($)
{
	my ($id) = @_;

	my $k = "000102030405060708090a0b0c0d0e0f";
	my $op = "00102030405060708090a0b0c0d0e0f0";

	$sth_auc_3g->execute($id, 5, $k, $op, 0);
}

sub create_subscr($$$)
{
	my ($imsi, $is_2g, $is_3g) = @_;
	my $suffix = substr($imsi, 5);

	create_subscr_base($imsi);

	my $id = $dbh->sqlite_last_insert_rowid();
	#$sth_subscr_get_id->execute($imsi);
	#my @arr = $sth_subscr_get_id->fetchrow_array();
	#my $id = $arr[0];

	if ($is_3g) {
		create_auc_3g($id);
	}
	if ($is_2g) {
		create_auc_2g($id);
	}
}


my $prefix = "90179";

$dbh->{AutoCommit} = 0;
$dbh->do("PRAGMA synchronous = OFF");

for (my $i = 0; $i < 1000000; $i++) {
	my $imsi = sprintf("%s%010u", $prefix, $i);
	if ($i % 1000 == 0) {
		printf("Creating subscriber IMSI %s\n", $imsi);
	}
	create_subscr($imsi, 1, 1);
}

$dbh->commit;
