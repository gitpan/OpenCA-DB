# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "0..6\n"; }
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

$ret = `./alpha.pl 2>&1 >../logs/log.2`;
if( $? != 0 ) { die "ERROR: not ok 2" };
print "ok .. 2\n";

$ret = `./beta.pl 2>&1 >../logs/log.3`;
if( $? != 0 ) { die "ERROR: not ok 3" };
print "ok .. 3\n";

$ret = `./gamma.pl 2>&1 >../logs/log.4`;
if( $? != 0 ) { die "ERROR: not ok 4" };
print "ok .. 4\n";

$ret = `./delta.pl 2>&1 >../logs/log.5`;
if( $? != 0 ) { die "ERROR: not ok 5" };
print "ok .. 5\n";

$ret = `./epsilon.pl 2>&1 >../logs/log.6`;
if( $? != 0 ) { die "ERROR: not ok 6" };
print "ok .. 6\n";

print "\nAll tests ok.\n\n";
exit 0;
