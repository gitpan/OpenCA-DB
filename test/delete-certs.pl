#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::REQ;
use OpenCA::DB;

my $shell = ( $ENV{OPENSSL} or "/usr/bin/openssl" );
my $cnf   = ( $ENV{OPENSSL_CONFIG} or "/usr/ssl/openssl.cnf");

my $openssl = new OpenCA::OpenSSL( SHELL=>$shell, CONFIG=> $cnf );
my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );

my @serials = ( 3 , 04 , 1 );
my @not_existing_ser = ( 4 , 15, 34 );
my ( $x509 );

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

print "* Deleting Certificates ( " .  
		$db->elements( DATATYPE=>"VALID_CERTIFICATE" ) . " ) :\n";

foreach ( @serials ) {
	print "   [ $_ ] ... ";
	if( not $db->deleteItem( DATATYPE=>"VALID_CERTIFICATE", KEY=>$_ )) {
		print "Error!\n";
		exit 1;
	}
	print "Deleted.\n";
}

print "* Deleting non existing certs ( " .  
		$db->elements( DATATYPE=>"VALID_CERTIFICATE" ) . " ) :\n";
foreach ( @not_existing_ser ) {
	print "   [ $_ ] ... ";
	if( $db->deleteItem( DATATYPE=>"VALID_CERTIFICATE", KEY=>$_ )) {
		print "Error!\n";
		exit 1;
	}
	print "Not Present.\n";
}
exit 0;

