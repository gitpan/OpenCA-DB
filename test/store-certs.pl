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

my @certs = ( "data/03.pem" , "data/04.pem", "data/01.pem" );
my @status = ( "VALID","EXPIRED","REVOKED" );

my ( $x509, $st );

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

foreach $st (@status) {
	print "\n* Storing " . lc($st) . " Certificates:\n";
	foreach $file (@certs) {
		$x509 = new OpenCA::X509( SHELL=>$openssl, INFILE=>"$file" );
		if ( not $x509 ) {
			print "Error!\n";
			exit 1;
		}

		print "   serial ($file)" . $x509->getParsed()->{SERIAL} . " ... ";
		if ( not $db->storeItem( OBJECT=>$x509, 
					DATATYPE=>"${st}_CERTIFICATE" )) {
			print "Error!\n";
			exit 1;
		}
		print "Ok.\n";
	}
}

exit 0;
