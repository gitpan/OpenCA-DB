#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::REQ;
use OpenCA::DB;

my $shell = ( $ENV{OPENSSL} or "/usr/bin/openssl" );
my $cnf   = ( $ENV{OPENSSL_CONFIG} or "/usr/ssl/openssl.cnf");
my $data  = "data";

my $openssl = new OpenCA::OpenSSL( SHELL=> $shell, CONFIG=>$cnf );
my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );

my $req;

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

$db->initDB();

## print "ELEMENTS: " . $db->elements( DATATYPE=>PENDING_REQUEST ) . "\n";

print "Delete Test ........ ";
if( not $db->deleteItem( DATATYPE=>PENDING_REQUEST, KEY=>1 )) {
	die "ERROR: Cannot delete Key $key\n";
} else {
	print "Ok.\n\n";
}

## print "ELEMENTS: " . $db->elements( DATATYPE=>PENDING_REQUEST ) . "\n";

## @list = $db->searchItem( DATATYPE=>PENDING_REQUEST, CN=>"Massimiliano Pala",
## 					EMAIL=>"madwolf\@openca.org" );

## for $i ( @list ) {
## 	print "Object Found: $i\n";
## }

