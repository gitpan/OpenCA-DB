#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::REQ;
use OpenCA::DB;

my $shell = ( `type -path openssl` or $ENV{OPENSSL} or "/usr/bin/openssl" );
my $cnf   = ( $ENV{OPENSSL_CONFIG} or "/usr/ssl/openssl.cnf");
my $data  = "data";

print "\nInitializing Crypto Backend ($shell) and dB object ... ";

my $openssl = new OpenCA::OpenSSL( SHELL=>$shell, CONFIG=>$cnf);
my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );

if( not $db or not $openssl ) {
	print "Error 1\n";
	print "(DB = $db ; OPENSSL = $openssl )";
	exit;
} else {
	print "Ok.\n";
}

print "Initializing DB ... ";
	$db->initDB( FORCE=>1);
print "Ok.\n";

my $r = new OpenCA::REQ( SHELL=>$openssl, FORMAT=>"SPKAC",
					INFILE=>"$data/spkac.req" );

if ( not $r ) {
	die "ERROR: Creating REQ (SPKAC) Object.\n";
}

print "\nAdding Objects:\n";
print "Adding Pending Request (1) .... ";
if( $ser = $db->storeItem( OBJECT=>$r, DATATYPE => PENDING_REQUEST,
			INFORM=>SPKAC )) {
	print "Ok (Ser. $ser)\n";
} else {
	print "ERROR: Storing PENDING_REQUEST (1) Object.\n";
}

my $r = new OpenCA::REQ( SHELL=>$openssl, FORMAT=>"SPKAC",
					INFILE=>"$data/spkac2.req" );
if ( not $r ) {
	die "Error (REQ)!\n";
}

print "Adding Pending Request (2) .... ";
if( $ser = $db->storeItem( OBJECT=>$r, DATATYPE => PENDING_REQUEST,
			INFORM=>SPKAC )) {
	print "Ok (Ser. $ser)\n";
} else {
	print "ERROR: Storing PENDING_REQUEST (2) Object.\n";
}

my $r = new OpenCA::REQ( SHELL=>$openssl, FORMAT=>"PEM",
						INFILE=>"$data/req2.pem" );
if ( not $r ) {
	die "Error (REQ)!\n";
}

print "Adding Pending Request (3) .... ";
if( $ser = $db->storeItem( OBJECT=>$r, DATATYPE => PENDING_REQUEST,
			INFORM=>PEM )) {
	print "Ok (Ser. $ser)\n";
} else {
	print "ERROR: Storing PENDING_REQUEST (3) Object.\n";
}

my $c = new OpenCA::X509( SHELL=>$openssl, FORMAT=>"PEM", 
						INFILE=>"$data/cert.pem" );
if ( not $c ) {
	die "Error (REQ)!\n";
}

print "Adding x509 Certificate (4) .... ";
if( $ser = $db->storeItem( OBJECT=>$c, DATATYPE => VALID_CERTIFICATE,
			INFORM=>PEM )) {
	print "Ok (Ser. $ser)\n";
} else {
	print "ERROR: Storing VALID_CERTIFICATE (4) Object.\n";
}

print "::: PIPPO";
my $crl = new OpenCA::CRL( SHELL=>$openssl, FORMAT=>PEM, 
						INFILE=>"$data/crl.pem" );
print "::: PIPPO";
if ( not $crl ) { die "ERROR: Creating CRL.\n" };

print "::: PIPPO";
my $r = new OpenCA::REQ( SHELL=>$openssl, FORMAT=>"SPKAC",
					INFILE=>"$data/spkac3.req" );
print "::: PIPPO";
if ( not $r ) {
	die "Error (REQ)!\n";
}

print "::: PIPPO";
print "Adding Deleted Request (5) .... ";
if( $ser = $db->storeItem( OBJECT=>$r, DATATYPE => DELETED_REQUEST,
			INFORM=>SPKAC )) {
	print "Ok (Ser. $ser)\n";
} else {
	print "ERROR: Storing PENDING_REQUEST (2) Object.\n";
}

print "Adding Valid CRL (1) .... ";
if ( $ser = $db->storeItem( OBJECT=>$crl, DATATYPE => VALID_CRL,
				FORMAT=>PEM )) {
	print "Ok (Ser. $ser)\n";
} else {
	print "ERROR: Storing CRL object\n\n";
}

print "\nRetrieving Objects:\n";
if ( not $item = $db->getItem( DATATYPE=>PENDING_REQUEST, KEY=>1 )) {
	print "ERROR: Getting PENDING_REQUEST Object (Serial 1)\n";
} else {
	print "OK: Got PENDING_REQUEST Object (Serial 1)\n";
}

if ( not $item = $db->getItem( DATATYPE=>DELETED_REQUEST, KEY=>1 )) {
	print "ERROR: Getting DELETED_REQUEST Object (Serial 1)\n";
} else {
	print "OK: Got PENDING_REQUEST Object (Serial 1)\n";
}

if ( not $item = $db->getItem( DATATYPE=>CRL, KEY=>1 )) {
	print "ERROR: Getting CRL Object (Serial 1)\n";
} else {
	print "OK: Got CRL Object (Serial 1)\n";
}

print "Done.\n\n";

exit 0;
