#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::REQ;
use OpenCA::DB;

my $shell = ( $ENV{OPENSSL} or "/usr/bin/openssl" );
my $cnf   = ( $ENV{OPENSSL_CONFIG} or "/usr/ssl/openssl.cnf");

my $openssl = new OpenCA::OpenSSL( SHELL=>$shell, CONFIG=>$cnf );
my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );

my $ret, $key=-1;

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

$db->initDB();

print "Get NextItem Test:\n";

print "ELEMENTS: " . $db->elements( DATATYPE=>PENDING_REQUEST ) . "\n";
while ( $ret = $db->getNextItem( DATATYPE=>PENDING_REQUEST, KEY=>$key )) {
	$key = $ret->getParsed()->{DBKEY};
	print "Got Item $key ($ret)\n";
	print "Searching Next Item $key\n";
}


