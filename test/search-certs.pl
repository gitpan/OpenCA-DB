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

my @status = ( "VALID" );
my ( $x509 );

my %search;

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

$search{'EMAIL'} = "madwolf\@openca.org";
$search{'CN'} = "Massimiliano Pala";
$search{'O'} = "OpenCA";

foreach $status (@status) {
	foreach (keys %search) {
		$key = $_;
		$val = $search{$key};

		print "\n* Searching " . lc( $status ) . " Certificates for " .
						"$key -> $val:\n";

		foreach $x509 ( $db->searchItems( DATATYPE=>"${status}_CERTIFICATE",
					$key=>$val )){
	 	 	print "   dbkey " . $x509->getParsed()->{DBKEY} 
				." ... $key - ". $x509->getParsed()->{DN}."\n"; 
		}
	}

}

exit 0;

