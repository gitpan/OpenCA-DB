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

my $openssl = new OpenCA::OpenSSL( SHELL=>$shell, CONFIG=>$cnf );
my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );

my $req;

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

$db->initDB();

print "Find/Search Elements Test:\n";

print "ELEMENTS: " . $db->elements( DATATYPE=>PENDING_REQUEST ) . "\n";

## print $db->deleteItem( DATATYPE=>PENDING_REQUEST, KEY=>1 );
## print "ELEMENTS: " . $db->elements( DATATYPE=>PENDING_REQUEST ) . "\n";

@list = $db->searchItems( DATATYPE=>PENDING_REQUEST,
					EMAIL=>"madwolf\@openca.org" );
for $i ( @list ) {
	print "Object Found: " . $i->getParsed()->{OPERATOR} . "\n";
}

@list = $db->searchItems( DATATYPE=>PENDING_REQUEST, RA=>"Anagrafe 1" );
for $i ( @list ) {
	print "Object Found: " . $i->getParsed()->{DN} . "\n";
}

print "ROWS on Prev Search: " . $db->rows( DATATYPE=>PENDING_REQUEST,
						RA=>"Anagrafe 1" ) . "\n";

@list = $db->listItems( DATATYPE=>PENDING_REQUEST, FROM=>, TO=>, ITEMS=>25 );
for $i ( @list ) {
	print "List Object Found: " . $i->getParsed()->{DBKEY} . "\n";
}

print "Ok.\n\n";

