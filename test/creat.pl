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

if( not $db or not $openssl ) {
	print "Error 1\n";
	exit;
}

$db->initDB( MODE => FORCE );
