#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::REQ;
use OpenCA::DB;

my $shell = ( $ENV{OPENSSL} or "/usr/bin/openssl" );
my $cnf   = ( $ENV{OPENSSL_CONFIG} or "/usr/ssl/openssl.cnf");

my $openssl = new OpenCA::OpenSSL( SHELL=>$shell, CONFIG=> $cnf, 
						STDERR=>"/dev/null" );
my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );

my @reqs =   ( "data/req.pem" , "data/req_32212.spkac" );
my @status = ( "PENDING","APPROVED","DELETED" );

my ( $req, $st );

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

foreach $st (@status) {
	print "\n* Storing " . lc($st) . " Requests:\n";
	foreach $file (@reqs) {
		$req = new OpenCA::REQ( SHELL=>$openssl, INFILE=>"$file" );
		if ( not $req ) {
			print "Error!\n";
			exit 1;
		}

		print "   request ($file)" . $req->getParsed()->{HEADER}->{TYPE} .
								 " ... ";
		if ( not $db->storeItem( OBJECT=>$req, 
					DATATYPE=>"${st}_REQUEST" )) {
			print "Error!\n";
			exit 1;
		}
		print "Ok.\n";
	}
}

exit 0;
