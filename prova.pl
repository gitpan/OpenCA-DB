#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::REQ;
use OpenCA::DB;

my $openssl = new OpenCA::OpenSSL;
my @tmpfiles = ("cert.pem","priv.key","req.pem");

print "Initializing crypto shell ... \n";
$openssl->setParams ( SHELL=>"/usr/local/ssl/bin/openssl",
		      CONFIG=>"/usr/local/mpcNET/stuff/openssl.cnf" );

$openssl->setParams ( STDERR => "/dev/null" );

print "Generating a 512 bit priv Key ...\n";
if( not $openssl->genKey( BITS=>512, OUTFILE=>"priv.key" ) ) {
 	print "Error\n";
}

print "Generating a Request file ... \n";
$openssl->genReq( OUTFILE=>"req.pem", KEYFILE=>"priv.key",
 		DN=>["madwolf\@openca.org", "Massimiliano Pala", "CA", "", "" ] );

print "Generating a CA certificate ... \n";
$p = $openssl->genCert( KEYFILE=>"priv.key", REQFILE=>"req.pem", DAYS=>150,
			OUTFILE=>"cert.pem");

print "Creating a new X509 object ... \n";
my $X509 = new OpenCA::X509( INFILE=>"cert.pem",
			     FORMAT=>"PEM", SHELL=>$openssl);

print " * Serial: " . $X509->getParsed()->{SERIAL} . "\n";
print " * Version: " . $X509->getParsed()->{VERSION} . "\n";
print " * Modulus: " . $X509->getParsed()->{MODULUS} . "\n";
print " * Exponent: " . $X509->getParsed()->{EXPONENT} . "\n";

print "Creating a new CRL Object ... \n";
my $CC = new OpenCA::CRL( SHELL=>$openssl, CACERT=>"cert.pem",
			  CAKEY=>"priv.key", DAYS=>"31" );
if( not $CC ) {
	print "Error!\n";
}

my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );

if( not $db ) {
        print "not ok 1\n";
        exit 1;
}

my $data = $CC->getPEM();

print "Storing Request ... \n";
my $r = new OpenCA::REQ( SHELL=>$openssl, FORMAT=>"SPKAC", INFILE=>"spkac.req" );

if( not $db->storeItem( DATATYPE=>PENDING_REQUEST, DATA=>$r->{req} ) ) {
  	print "13 ....... not ok 13\n";
   	exit;
}

print "Storing CRL to DB ....\n";
if( not $db->storeItem( DATATYPE=>CRL, DATA=>$data ) ) {
   	print "14 ....... not ok 14\n";
}

## print "Retrieving the CRL from the DB ... \n";
## @list = $db->searchItem( DATATYPE=>CRL, LAST_UPDATE=>"Feb 16 12:18" );

## my $testDate = "May 10 10:25:32 2000";
## my $testDate = "Sun Apr 30 23:05:38 2000 GMT";

## @list = $db->searchItem( DATATYPE=>CRL, DATE=>$testDate );
@list = $db->searchItem( DATATYPE=>CRL );

$total    = $db->elements( DATATYPE=>CRL );
## $elements = $db->rows( DATATYPE=>CRL, DATE=>$testDate );
$elements = $db->rows( DATATYPE=>CRL );

print "Retrieved $elements on $total elements ...\n";
foreach $crl (@list) {
	print "\n";
	print " * dB Key:      $crl->{KEY}\n";
	print " * Version:     " . $crl->{VALUE}->getParsed()->{VERSION} . "\n";
	print " * Type:        " . $crl->{DATATYPE} . "\n";
	print " * Last Update: ".$crl->{VALUE}->getParsed()->{LAST_UPDATE}."\n";
	print " * Next Update: ".$crl->{VALUE}->getParsed()->{NEXT_UPDATE}."\n";
	print "\n";
}

## @list = $db->searchItem( DATATYPE=>REQUEST );
## $elements = $db->elements( DATATYPE=>REQUEST );

## print "Retrieved $elements elements ...\n";
## foreach $crl (@list) {
## 	print "\n";
## 	print " * dB Key:      $crl->{KEY}\n";
## 	print " * Type:        " . $crl->{DATATYPE} . "\n";
## 	print " * Version:     " . $crl->{VALUE}->getParsed()->{VERSION} . "\n";
## 	print " * CN:          ".$crl->{VALUE}->getParsed()->{CN}."\n";
## 	print " * Modulus:     ".$crl->{VALUE}->getParsed()->{MODULUS}."\n";
## 	print " * Approved:    ".$crl->{VALUE}->getParsed()->{APPROVED}."\n";
## 	print "\n";
## }

print "Unlinking temp files ... \n";

foreach $tmp (@tmpfiles) {
	unlink( "$tmp" );
}

print "Ok.\n\n";

print "dB Status:\n\n";

print "STATUS   => " . $db->getItem( DATATYPE =>CRL, KEY=>STATUS ) . "\n";
print "INIT     => " . $db->getItem( DATATYPE =>CRL, KEY=>INIT ) . "\n";
print "MODIFIED => " . $db->getItem( DATATYPE =>CRL, KEY=>MODIFIED ) . "\n";
print "DELETED  => " . $db->getItem( DATATYPE =>CRL, KEY=>DELETED ) . "\n";
print "ELEMENTS => " . $db->elements( DATATYPE => CRL ) . "\n";
print "SERIAL   => " . $db->getSerial( DATATYPE => CRL ) . "\n\n";

exit 0; 

