# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "0..8\n"; }
END {print "not ok 1\n" unless $loaded;}

use OpenCA::DB;
$loaded = 1;
print "ok .. 0\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

chdir "test/" or die "ERROR: cannot change dir to test/";

$ret = `./creat.pl 2>&1 >../logs/log.1`;
if( $? != 0 ) { die "ERROR: not ok 1" };
print "ok .. 1\n";

$ret = `./store-certs.pl 2>&1 >../logs/log.2`;
if( $? != 0 ) { die "ERROR: not ok 2" };
print "ok .. 2\n";

$ret = `./list-certs.pl 2>&1 >../logs/log.3`;
if( $? != 0 ) { die "ERROR: not ok 3" };
print "ok .. 3\n";

$ret = `./search-certs.pl 2>&1 >../logs/log.4`;
if( $? != 0 ) { die "ERROR: not ok 4" };
print "ok .. 4\n";

$ret = `./store-reqs.pl 2>&1 >../logs/log.5`;
if( $? != 0 ) { die "ERROR: not ok 5" };
print "ok .. 5\n";

$ret = `./list-reqs.pl 2>&1 >../logs/log.6`;
if( $? != 0 ) { die "ERROR: not ok 6" };
print "ok .. 6\n";

$ret = `./delete-reqs.pl 2>&1 >../logs/log.7`;
if( $? != 0 ) { die "ERROR: not ok 7" };
print "ok .. 7\n";

$ret = `./delete-certs.pl 2>&1 >../logs/log.8`;
if( $? != 0 ) { die "ERROR: not ok 8" };
print "ok .. 8\n";

print "\nAll tests ok.\n\n";
print "(removing db files)\n\n";
`rm -rf db/*_*`;

exit 0;
