#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::REQ;
use OpenCA::DB;

my $shell = ( $ENV{OPENSSL} or "/usr/bin/openssl" );
my $cnf   = ( $ENV{OPENSSL_CONFIG} or "/usr/ssl/openssl.cnf");

my $openssl = new OpenCA::OpenSSL( SHELL=>$shell,CONFIG=>$cnf,STDERR=>"/dev/null");
my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );

my @status = ( "PENDING", "APPROVED", "DELETED" );
my ( $req );

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

foreach (@status) {

	print "\n* Listing " . lc( $_ ) . " Requests ( elements " .  
		$db->elements( DATATYPE=>"${_}_REQUEST" ) . " ) :\n";

	foreach $req ( $db->listItems( DATATYPE=>"${_}_REQUEST" )) {
	 	print "   dbkey " . $req->getParsed()->{DBKEY} . " ...  " . 
			$req->getParsed()->{CN} . "\n"; 
	}

	print "* Listing " . lc( $_ ) . " Requests from 4 ( elements " .  
			$db->elements( DATATYPE=>"${_}_REQUEST" ) . " ) :\n";
	
	foreach $req ( $db->listItems( DATATYPE=>"${_}_REQUEST", FROM=>4 )) {
	 	print "   dbkey " . $req->getParsed()->{DBKEY} . " ...  " . 
			$req->getParsed()->{CN} . "\n"; 
	}

	print "* Listing " . lc( $_ ) . " Requests with items 2 ( elements " .  
			$db->elements( DATATYPE=>"${_}_REQUEST" ) . " ) :\n";

	foreach $req ( $db->listItems( DATATYPE=>"${_}_REQUEST", ITEMS=>2 )) {
 		print "   dbkey " . $req->getParsed()->{DBKEY} . " ...  " . 
			$req->getParsed()->{CN} . "\n"; 
	}

	print "* Listing " . lc( $_ ) . " Requests with items 1 from 3 ( elements " .  
			$db->elements( DATATYPE=>"${_}_REQUEST" ) . " ) :\n";

	foreach $req ( $db->listItems( DATATYPE=>"${_}_REQUEST", ITEMS=>1,
					FROM=>3 )) {
 		print "   dbkey " . $req->getParsed()->{DBKEY} . " ...  " . 
			$req->getParsed()->{CN} . "\n"; 
	}
}

exit 0;

