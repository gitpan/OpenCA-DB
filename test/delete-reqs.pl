#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::REQ;
use OpenCA::DB;

my $shell = ( $ENV{OPENSSL} or "/usr/bin/openssl" );
my $cnf   = ( $ENV{OPENSSL_CONFIG} or "/usr/ssl/openssl.cnf");

my $openssl = new OpenCA::OpenSSL(SHELL=>$shell,CONFIG=>$cnf,STDERR=>"/dev/null" );
my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );

my @serials = ( "" , 32212 );
my @not_existing_ser = ( 50, 321 );

my @status = ( "PENDING", "APPROVED", "DELETED" );

my ( $req );

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

foreach $st ( @status ) {

	print "* Deleting " . lc( $st ) . " Requests ( " .  
		$db->elements( DATATYPE=>"${st}_REQUEST" ) . " ) :\n";

	foreach ( @serials ) {
		print "   [ $_ ] ... ";
		if( not $db->deleteItem( DATATYPE=>"${st}_REQUEST", KEY=>$_ )) {
			print "Error!\n";
			exit 1;
		}
		print "Deleted.\n";
	}

	print "* Deleting non existing " . lc( $st ) . " requests ( " .  
		$db->elements( DATATYPE=>"${st}_REQUEST" ) . " ) :\n";
	foreach ( @not_existing_ser ) {
		print "   [ $_ ] ... ";
		if( $db->deleteItem( DATATYPE=>"${st}_REQUEST", KEY=>$_ )) {
			print "Error!\n";
			exit 1;
		}
		print "Not Present.\n";
	}
}

exit 0;

