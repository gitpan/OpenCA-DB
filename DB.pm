## OpenCA::DB
##
## Copyright (C) 1998-1999 Massimiliano Pala (madwolf@openca.org)
## All rights reserved.
##
## This library is free for commercial and non-commercial use as long as
## the following conditions are aheared to.  The following conditions
## apply to all code found in this distribution, be it the RC4, RSA,
## lhash, DES, etc., code; not just the SSL code.  The documentation
## included with this distribution is covered by the same copyright terms
## 
## Copyright remains Massimiliano Pala's, and as such any Copyright notices
## in the code are not to be removed.
## If this package is used in a product, Massimiliano Pala should be given
## attribution as the author of the parts of the library used.
## This can be in the form of a textual message at program startup or
## in documentation (online or textual) provided with the package.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##    must display the following acknowledgement:
##    "This product includes OpenCA software written by Massimiliano Pala
##     (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
## 4. If you include any Windows specific code (or a derivative thereof) from 
##    some directory (application code) you must include an acknowledgement:
##    "This product includes OpenCA software (www.openca.org)"
## 
## THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## 
## The licence and distribution terms for any publically available version or
## derivative of this code cannot be changed.  i.e. this code cannot simply be
## copied and put under another distribution licence
## [including the GNU Public Licence.]

package OpenCA::DB;

## We must store/retrieve CRLs,CERTs,REQs objects:
## proper instances of object management classes are
## needed.

use OpenCA::REQ;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::CRR;
use OpenCA::OpenSSL;
use OpenCA::Tools;

$VERSION = '0.5.51';

my %params = {
 dbDir => undef,
 backend => undef,
 dBs => undef,
 defStoredFormat => undef,
 defOutFormat => undef,
 tools => undef,
 };

sub new {
        my $that = shift;
	my $class = ref($that) || $that;

	my $self = {
		%params,
	};

        bless $self, $class;

        my $keys = { @_ };

        $self->{backend}   = $keys->{SHELL};
        $self->{dbDir}     = $keys->{DB_DIR};

        return if ((not $self->{backend}) or (not $self->{dbDir}));

	$self->{dBs}->{VALID_CERTIFICATE}->{FILE}	= "valid_certs";
	$self->{dBs}->{REVOKED_CERTIFICATE}->{FILE}	= "revoked_certs";
	$self->{dBs}->{EXPIRED_CERTIFICATE}->{FILE}	= "expired_certs";
	$self->{dBs}->{SUSPENDED_CERTIFICATE}->{FILE}	= "suspended_certs";

	$self->{dBs}->{VALID_CA_CERTIFICATE}->{FILE}	= "ca_certs";
	$self->{dBs}->{EXPIRED_CA_CERTIFICATE}->{FILE}	= "expired_ca_certs";

	$self->{dBs}->{PENDING_REQUEST}->{FILE}		= "pending_reqs";
	$self->{dBs}->{DELETED_REQUEST}->{FILE}		= "deleted_reqs";
	$self->{dBs}->{APPROVED_REQUEST}->{FILE}	= "approved_reqs";
	$self->{dBs}->{ARCHIVIED_REQUEST}->{FILE}	= "archivied_reqs";
	$self->{dBs}->{RENEW_REQUEST}->{FILE}		= "renew_reqs";

	$self->{dBs}->{PENDING_CRR}->{FILE}		= "pending_crrs";
	$self->{dBs}->{ARCHIVIED_CRR}->{FILE}		= "archivied_crrs";
	$self->{dBs}->{DELETED_CRR}->{FILE}		= "deleted_crrs";

	$self->{dBs}->{CRL}->{FILE}			= "archivied_crls";

	## Defaults storage format. This does not apply to SPKAC requests
	$self->{defStoredFormat} 		= "DER";
	$self->{defOutFormat}    		= "PEM";

	if( not ( opendir( DIR, $self->{dbDir} ))) {
		return;
	} else {
		closedir(DIR);
	};

	return if ( not $self->{tools} = new OpenCA::Tools());

	return $self;
}

sub storeItem {

	## Store a provided Item (DATA) provided the exact
	## DATATYPE. KEY (position in dB) data to match will
	## be automatically chosen on a DATATYPE basis.

	## The INFORM is used to get the data input format
	## PEM|DER|NET|SPKAC

	my $self = shift;
	my $keys = { @_ };

	my $type = $keys->{DATATYPE};
	my @ret = ();
	my $tmp;

	return if ( not exists $self->{dBs}->{$type} );

	my $dbFile = $self->{dBs}->{$type}->{FILE};

	## Data is stored in DER format when available. The only
	## DATATYPE not DER capable, actually, is the SPKAC...
	## be careful when retrieving REQUESTS.

	return $self->storeItemDB( DB_FILENAME=>$dbFile, @_ );
}

sub storeItemDB {

	## Get an item from a DB provided dbFileName and KEY value
	my $self = shift;
	my $keys = { @_ };

	my $type       = $keys->{DATATYPE};
	my $inform     = $keys->{INFORM};
	my $dbFileName = $keys->{DB_FILENAME};
	my $data       = $keys->{DATA};
	my $dbDir      = $self->{dbDir};

	my $converted, $tmp, %DB;

	## Shall we give the ability to choose directly the
	## key ??? This is actually left out to provide a
	## very independent interface class... (huh?)
	my $key     = $keys->{KEY};

	return if( (not $dbFileName) or (not $data));

	$dbFileName = "$dbDir/$dbFileName";

	if( ($type =~ /REQUEST/) and ( $data =~ /SPKAC = / )) {
		$inform = "SPKAC";
		$converted = $data;
	} elsif ( ($type =~ /REQUEST/) and ( $data =~ /RENEW = / )) {
		$inform = "RENEW";
		$converted = $data;
	} else {
		$inform = "PEM" if( not $inform );
		$converted = $self->{backend}->dataConvert( DATA=>$data,
					DATATYPE=>$type,
					INFORM=>$inform,
					OUTFORM=>DER );
	}

	if( $type =~ /CA_CERTIFICATE/i ) {
		$obj = new OpenCA::X509( SHELL=>$self->{backend},
			        INFORM=>$inform,
			        DATA=>$data );
		$key = $self->{backend}->getDigest( DATA=>$data )
							if( not $key );

	} elsif( $type =~ /CERTIFICATE/i ) {
		$obj = new OpenCA::X509( SHELL=>$self->{backend},
			        INFORM=>$inform,
			        DATA=>$data );
		$key = $obj->getParsed()->{SERIAL}
					if( not $key );

	} elsif ( $type =~ /CRL/i ) {
		$obj = new OpenCA::X509( SHELL=>$self->{backend},
			        INFORM=>$inform,
			        DATA=>$data );
		## $key = $self->{backend}->getDigest( DATA=>$data )
		##					if( not $key );

		$key = $self->getSerial( DATATYPE=>$type ) if (not $key);

	} elsif ( $type =~ /REQUEST/i ) {
		$obj = new OpenCA::REQ( SHELL=>$self->{backend},
			        INFORM=>$inform,
			        DATA=>$data );

		$key = $self->getSerial( DATATYPE=>$type ) if (not $key);

	} elsif ( $type =~ /CRR/i ) {
		$obj = new OpenCA::CRR( $data );
		$key = $obj->getParsed()->{CERTIFICATE_SERIAL}
							if( not $key );
	}

	return if ( not $key );

	dbmopen( %DB, "$dbFileName", 0600 ) or return ;

		if( not $DB{$key} ) {
			my $tmpNum, $tmpHex;

			if( not $DB{SERIAL} ) {
				$DB{SERIAL}="01";
			} else {
				$tmpNum = hex( $DB{SERIAL} );
				$tmpNum++;

				$DB{SERIAL} = $self->toHex( $tmpNum );
			}

			if( not $DB{DELETED} ) {
				$DB{DELETED}=0;
			}
				
			if( not $DB{ELEMENTS} ) {
				$DB{ELEMENTS}=1;

				$DB{INIT}=$self->{tools}->getDate();

				$DB{STATUS}="Updated";
			} else {
				$tmpNum = $DB{ELEMENTS};
				$tmpNum++;

				$DB{ELEMENTS}=$tmpNum;
			}

		}
		$DB{MODIFIED}=$self->{tools}->getDate();
		$DB{$key}="$data";
	dbmclose( %DB );

	return $key;

}


sub deleteItem {

	## Store a provided Item (DATA) provided the exact
	## DATATYPE. KEY (position in dB) data to match will
	## be automatically chosen on a DATATYPE basis.

	## The INFORM is used to get the data input format
	## PEM|DER|NET|SPKAC

	my $self = shift;
	my $keys = { @_ };
	my $dbDir = $self->{dbDir};

	my $type = $keys->{DATATYPE};
	my @ret = ();
	my $tmp;

	return if ( not exists $self->{dBs}->{$type} );

	my $dbFile = $self->{dBs}->{$type}->{FILE};

	## Data is stored in DER format when available. The only
	## DATATYPE not DER capable, actually, is the SPKAC...
	## be careful when retrieving REQUESTS.

	return $self->deleteItemDB( DB_FILENAME=>$dbFile, @_ );
}

sub deleteItemDB {

	## Get an item from a DB provided dbFileName and KEY value
	my $self = shift;
	my $keys = { @_ };

	my $type       = $keys->{DATATYPE};
	my $key        = $keys->{KEY};
	my $dbFileName = $keys->{DB_FILENAME};
	my $dbDir      = $self->{dbDir};

	my $ret, %DB;

	return if( (not $dbFileName) or (not $key));

	$dbFileName = "$dbDir/$dbFileName";

	dbmopen( %DB, "$dbFileName", 0600 ) or return ;
		if( $DB{$key} ) {

			if( not $DB{ELEMENTS} ) {
				$DB{ELEMENTS}=0;
			} else {
				$DB{ELEMENTS}--;
			}

			if( not $DB{DELETED} ) {
				$DB{DELETED}=1;
			} else {
				$DB{DELETED}++;
			}

			$DB{STATUS}="Needs Updating";

			$DB{MODIFIED}=$self->{tools}->getDate();
		}
		delete( $DB{$key} );
	dbmclose( %DB );

	return 1;

}

sub getItem {

	## Get an Item provided the exact data to match:
	## DATATYPE, KEY. Will return, if exists, the data
	## on the corresponding dB file.

	## Actually, as the search function, the returned
	## value will be a referenced object (REQ, X509,
	## CRL, etc... ).

	my $self = shift;
	my $keys = { @_ };
	my $dbDir = $self->{dbDir};

	my $tmp, $elem;

	my $type   = $keys->{DATATYPE};
	my $key    = $keys->{KEY};

	return if ( not exists $self->{dBs}->{$type} );

	my $dbFile = $self->{dBs}->{$type}->{FILE};

	$tmp = $self->getItemDB( DB_FILENAME=>$dbFile, KEY=>$key );

	if( $type =~ /CERTIFICATE/i ) {
		$elem = new OpenCA::X509( SHELL=>$self->{backend},
			 	          INFORM=>$self->{defStoredFormat},
			        	  DATA=>$tmp );
	} elsif ( $type =~ /CRL/i ) {
		$elem = new OpenCA::CRL( SHELL=>$self->{backend},
			        	 INFORM=>$self->{defStoredFormat},
			        	 DATA=>$tmp );
	} elsif ( $type =~ /CRR/i ) {
		$elem = new OpenCA::CRR( SHELL=>$self->{backend},
			        	 DATA=>$tmp );
	} elsif ( $type =~ /REQUEST/i ) {
		$format = $self->{defStoredFormat};

		$format = "SPKAC" if( $tmp =~ /SPKAC =/ );
		$format = "RENEW" if( $tmp =~ /RENEW =/ );
		$elem = new OpenCA::REQ( SHELL=>$self->{backend},
			        	 INFORM=>$format,
			        	 DATA=>$tmp );
	} else {
		return;
	}

	return $tmp if( not $elem );

	## We return it if it is an SPKAC request ...
	return $elem;

}

sub getItemDB {

	## Get an item from a DB provided dbFileName and KEY value
	my $self = shift;
	my $keys = { @_ };

	my $dbFileName = $keys->{DB_FILENAME};
	my $key	       = $keys->{KEY};
	my $dbDir      = $self->{dbDir};

	my $ret, %DB;

	return if( (not $dbFileName) or (not $key));

	$dbFileName = "$dbDir/$dbFileName";

	dbmopen( %DB, "$dbFileName", 0600 ) or return;
		$ret = $DB{$key};
	dbmclose( %DB );

	return $ret;

}

sub searchItem {

	## Returns the requested item LIST. You can search for
	## generic DATATYPE such as CERTIFICATE|REQUEST|CRL
	## or restricted type (EXPIRED_CERTIFICATE|REVOKED_CERTIFICATE|
	## VALID_CERTIFICATE...

	my $self = shift;
	my $keys = { @_ };
	my $dbDir = $self->{dbDir};

	my @retList = ();
	my $dataType;

	my $type   = $keys->{DATATYPE};

	foreach $dataType ( keys %{ $self->{dBs}} ) {
		if ( $dataType =~ /$type/i ) {
			my @plist = $self->searchDB( REAL_DATATYPE=>$dataType,
				DB_FILENAME=>$self->{dBs}->{$dataType}->{FILE},
					@_ );
			push @retList, @plist;
		}
	}

	return @retList;
}

sub elements {

	## Returns number of elements contained in a dB. This number
	## is stored in the ELEMENTS key and it is updated each time
	## the dB module operates on the db.

	my $self = shift;
	my $keys = { @_ };

	my $ret = 0;
	my $type = $keys->{DATATYPE};

	my $dbFile = $self->{dBs}->{$type}->{FILE};

	return if ( not exists $self->{dBs}->{$type} );

	$ret = $self->getItemDB( DB_FILENAME=>$dbFile, KEY=>'ELEMENTS' );
	$ret = 0 if( not $ret );

	return $ret;

}

sub getSerial {

	## Returns number of elements contained in a dB. This number
	## is stored in the ELEMENTS key and it is updated each time
	## the dB module operates on the db.

	my $self = shift;
	my $keys = { @_ };

	my $ret = 0;
	my $type = $keys->{DATATYPE};

	my $dbFile = $self->{dBs}->{$type}->{FILE};

	return if ( not exists $self->{dBs}->{$type} );

	$ret = $self->getItemDB( DB_FILENAME=>$dbFile, KEY=>'SERIAL' );
	$ret = '00' if( not $ret );

	return $ret;

}

sub rows {

	## Returns the number of item matching the request. You can search
	## for generic DATATYPE such as CERTIFICATE|REQUEST|CRL
	## or restricted type (EXPIRED_CERTIFICATE|REVOKED_CERTIFICATE|
	## VALID_CERTIFICATE...
	##
	## This function should be used in conjunction with searching function
	## use the elements sub instead if you wish to know how many specific
	## dB elements are there (such as VALID_CERTIFICATES, etc ... )

	my $self = shift;
	my $keys = { @_ };
	my $dbDir = $self->{dbDir};

	my $ret = 0;
	my $tmp;

	my $type   = $keys->{DATATYPE};

	foreach $dataType ( keys %{ $self->{dBs} } ) {

		if ( $dataType =~ /$type/i ) {
			my $elements = $self->searchDB(REAL_DATATYPE=>$dataType,
				DB_FILENAME=>$self->{dBs}->{$dataType}->{FILE},
				MODE=>ROWS,
				@_ );

			$ret += $elements if( $elements > 0 );
		}
	}

	return $ret;
}

sub searchDB {
	my $self = shift;
	my $keys = { @_ };

	my $type     = $keys->{REAL_DATATYPE};
	my $fileName = $keys->{DB_FILENAME};
	my $mode     = $keys->{MODE};
	my $from     = $keys->{FROM};
	my $to       = $keys->{TO};
	my $maxItems = $keys->{MAX_ITEMS};

	## Passed are regular expression to be matched...
	my $key        = $keys->{KEY};
	my $serial     = $keys->{SERIAL};
	my $dn         = $keys->{DN};
	my $CN         = $keys->{CN};
	my $OU         = $keys->{OU};
	my $O          = $keys->{O};
	my $C          = $keys->{C};
	my $notBefore  = $keys->{NOT_BEFORE};
	my $notAfter   = $keys->{NOT_AFTER};
	my $lastUpdate = $keys->{LAST_UPDATE};
	my $nextUpdate = $keys->{NEXT_UPDATE};
	my $date       = $keys->{DATE};

	my $tmp, $ret = 0, $counter = 0;
	my $matched, $i;
	my @retList = ();
	my $dbDir = $self->{dbDir};
	my $dbValue, $dbKey, $itNum;
	my %DB;

	$fileName = "$dbDir/$fileName";

	## Match HASH used to match item
	my $match = $keys;
	delete( $match->{DATATYPE} );
	delete( $match->{REAL_DATATYPE} );
	delete( $match->{DB_FILENAME} );
	delete( $match->{MODE} );
	delete( $match->{FROM} );
	delete( $match->{TO} );
	delete( $match->{MAX_ITEMS} );

	$itNum = $self->elements( DATATYPE=>$type );

	dbmopen( %DB, "$fileName", 0600 ) or return;
	if( ( $type =~ /CERTIFICATE|REQUEST|CRL/ )
				and ( $type !~ /CA_CERTIFICATE/)
				and ( $type !~ /EXPIRED_CA_CERTIFICATE/) ) {

		$from = 0 if ( not $from );
		$to = $self->elements( DATATYPE=>$type ) if (not $to);

		if( ( $maxItems) and ( $to > ($from + $maxItems )) ) {
			$to = $from + $maxItems;
		}


		for( $i = $from; $i <= $to ; $i++ ) {

			$dbKey = $self->toHex( $i );

			if (not $dbValue = $DB{$dbKey} ) {
				$to++ if ( $to < hex($self->toHex($itNum)) );
				next;
			}

			next if ( not $elem = $self->getElement(
							DATATYPE=>$type,
				    			DATA=>$dbValue ));

			$matched = $self->matches( $elem, $type, $match );

			if( $matched ) {
				my $item = { KEY=>$dbKey, 
					     VALUE=>$elem,
					     DATATYPE=>$type };

				if( "$mode" eq "ROWS" ) {
					$ret++;
				} else {
					push @retList, $item;
				}
			}
		}

	##} elsif ( $type =~ /CRL/ ) {
	##	foreach $dbValues ( sort byLastUpdate values %DB ) {
	##		
	##		print "::: KEY => $dbValue<BR>\n";

	##		next if ( not $elem = $self->getElement(
	##						DATATYPE=>$type,
	##			    			DATA=>$dbValue ));

	##		$matched = $self->matches( $elem, $type, $match );

	##		if( $matched ) {
	##			my $item = { KEY=>$dbKey, 
	##				     VALUE=>$elem,
	##				     DATATYPE=>$type };

	##			if( "$mode" eq "ROWS" ) {
	##				$ret++;
	##			} else {
	##				push @retList, $item;
	##			}
	##		}
	##	}
	} else {
		$maxItems-- if( $maxItems );

	    	while ( ($dbKey, $dbValue) = each  %DB ) {
			my $elem, $parsedItem;

			$counter++;

			next  if( ($from) and ($counter < $from) );
			break if( ($to) and ($counter > $to) );
			last if ( ($maxItems) and ($#retList >= $maxItems) );

			next if ( not $elem = $self->getElement(
							DATATYPE=>$type,
				    			DATA=>$dbValue ));

			$matched = $self->matches( $elem, $type, $match );

			if( $matched ) {
				my $item = { KEY=>$dbKey, 
					     VALUE=>$elem,
					     DATATYPE=>$type };

				if( "$mode" eq "ROWS" ) {
					$ret++;
				} else {
					push @retList, $item;
				}
			}
	    	}
	}
	dbmclose( %DB );

	if( "$mode" eq "ROWS" ) {
		return $ret;
	} else {
		return @retList;
	}
};

sub getElement {

	my $self = shift;

	my $keys = { @_ };
	my $type = $keys->{DATATYPE};
	my $data = $keys->{DATA};
	my $elem;

	if( $type =~ /CERTIFICATE/i ) {
		$elem = new OpenCA::X509( SHELL=>$self->{backend},
			        INFORM=>$self->{defStoredFormat},
			        DATA=>$data    );
	} elsif ( $type =~ /CRL/i ) {
		$elem = new OpenCA::CRL( SHELL=>$self->{backend},
			        INFORM=>$self->{defStoredFormat},
			        DATA=>$data    );
	} elsif ( $type =~ /CRR/i ) {
		$elem = new OpenCA::CRR( SHELL=>$self->{backend},
			        INFORM=>$self->{defStoredFormat},
			        DATA=>$data    );
	} elsif ( $type =~ /REQUEST/i ) {
		$format = $self->{defStoredFormat};

		$format = "SPKAC" if( $data    =~ /SPKAC =/ );
		$format = "RENEW" if( $data    =~ /RENEW =/ );
		$elem = new OpenCA::REQ( SHELL=>$self->{backend},
			        INFORM=>$format,
			        DATA=>$data    );
	}

	return $elem;
}


sub matches {

	my $self = shift;
	my $item = shift;
	my $type = shift;
	my $match = shift;

	my $parsedItem;
	my $ret = 1;

	return if (not $item);

	$parsedItem = $item->getParsed();
	return if ( not $parsedItem );

	foreach $key (keys %$match) {
		my $tmpMatch;

		if( $key ne "DATE" ) {
			next if( (not exists($parsedItem->{$key}))
		      		or (not exists($match->{$key})) );
		}

		$tmpMatch = $match->{$key};

		if( $key =~ /NOT_BEFORE|LAST_UPDATE/ ){
			if( $self->{tools}->cmpDate(
					DATE_1=>$parsedItem->{$key},
					DATE_2=>$tmpMatch ) > 0 ) {	
				$ret = 0;
				last;
			}

		} elsif( $key =~ /NOT_AFTER|NEXT_UPDATE/ ){

			if( $self->{tools}->cmpDate(
					DATE_1=>$parsedItem->{$key},
					DATE_2=>$tmpMatch ) < 0 ) {	

				$ret = 0;
				last;
			}

		} elsif( $key =~ /DATE/ ){

			my $startDate, $endDate;

			if( $type =~ /CRL/ ) {
				$startDate = $parsedItem->{LAST_UPDATE};
				$endDate = $parsedItem->{NEXT_UPDATE};
			} else {
				$startDate = $parsedItem->{NOT_BEFORE};
				$endDate = $parsedItem->{NOT_AFTER};
			}

			if( not $self->{tools}->isInsidePeriod(
				DATE=>$tmpMatch, START=>$startDate,
						END=>$endDate)) {

				$ret = 0;
				last;
			}

		} elsif( $parsedItem->{$key} !~ /$tmpMatch/i ) {

			$ret = 0;
			last;
		}
	}

	return $ret;

}

sub byKey { $a->{KEY} <=> $b->{KEY} };

sub getTimeString {

	my $self = shift;
	my $ret, @T;

	@T = gmtime( time() );
	$ret = sprintf( "%4.4d%2.2d%2.2d%2.2d%2.2d%2.2d%6.6d",
			 $T[5]+1900, $T[4], $T[3], $T[2], $T[1], $T[0], ${$} );

	return $ret;

}

sub toHex {

	my $self = shift;
	my $decimal = shift;
	my $ret;

	return "00" if ( not $decimal);

	$ret = sprintf( "%lx", $decimal );

	if( length( $ret ) % 2 ) {
		$ret = "0" . $ret;
	}

	$ret = uc( $ret );

	return $ret;

}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

OpenCA::DB - Perl Certificates DB Extention.

=head1 SYNOPSIS

use OpenCA::DB;

=head1 DESCRIPTION

Sorry, no documentation available at the moment. Please take a look
at the prova.pl program you find in main directory of the package.

=head1 AUTHOR

Massimiliano Pala <madwolf@openca.org>

=head1 SEE ALSO

OpenCA::OpenSSL, OpenCA::X509, OpenCA::CRL, OpenCA::REQ,
OpenCA::TRIStateCGI, OpenCA::Configuration, OpenCA::Tools

=cut
