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

my @status = ( "VALID", "REVOKED", "EXPIRED" );
my ( $x509 );

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

foreach (@status) {

	print "\n* Listing " . lc( $_ ) . " Certificates ( elements " .  
		$db->elements( DATATYPE=>"${_}_CERTIFICATE" ) . " ) :\n";

	foreach $x509 ( $db->listItems( DATATYPE=>"${_}_CERTIFICATE" )) {
	 	print "   dbkey " . $x509->getParsed()->{DBKEY} . " ... serial " . 
			$x509->getParsed()->{SERIAL} . "\n"; 
	}

	print "* Listing " . lc( $_ ) . " Certificates from 4 ( elements " .  
			$db->elements( DATATYPE=>"${_}_CERTIFICATE" ) . " ) :\n";
	
	foreach $x509 ( $db->listItems( DATATYPE=>"${_}_CERTIFICATE", FROM=>4 )) {
	 	print "   dbkey " . $x509->getParsed()->{DBKEY} . " ... serial " . 
			$x509->getParsed()->{SERIAL} . "\n"; 
	}

	print "* Listing " . lc( $_ ) . " Certificates with items 2 ( elements " .  
			$db->elements( DATATYPE=>"${_}_CERTIFICATE" ) . " ) :\n";

	foreach $x509 ( $db->listItems( DATATYPE=>"${_}_CERTIFICATE", ITEMS=>2 )) {
 		print "   dbkey " . $x509->getParsed()->{DBKEY} . " ... serial " . 
			$x509->getParsed()->{SERIAL} . "\n"; 
	}

	print "* Listing " . lc( $_ ) . " Certificates with items 1 from 3 ( elements " .  
			$db->elements( DATATYPE=>"${_}_CERTIFICATE" ) . " ) :\n";

	foreach $x509 ( $db->listItems( DATATYPE=>"${_}_CERTIFICATE", ITEMS=>1,
					FROM=>3 )) {
 		print "   dbkey " . $x509->getParsed()->{DBKEY} . " ... serial " . 
			$x509->getParsed()->{SERIAL} . "\n"; 
	}
}

exit 0;

