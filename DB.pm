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

use strict;

package OpenCA::DB;

## This should provide with fallback from BrekeleyDB->GDBM->NDBM
## Also should fix some Solaris Related problems... please report
## if you find this causing problems.
BEGIN { @AnyDBM_File::ISA = qw( DB_File GDBM_File NDBM_File ) }

## We must store/retrieve CRLs,CERTs,REQs objects:
## proper instances of object management classes are
## needed.

use OpenCA::REQ;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::CRR;
use OpenCA::OpenSSL;
use OpenCA::Tools;
use AnyDBM_File;

$OpenCA::DB::VERSION = '1.02';

my %params = {
 dbDir => undef,
 backend => undef,
 dBs => undef,
 defStoredFormat => undef,
 defOutFormat => undef,
 tools => undef,
 beginHeader => undef,
 endHeader => undef,
 idxDataType => undef,
 idxData =>undef,
};

sub new {
        my $that = shift;
	my $class = ref($that) || $that;

	my $self = {
		%params,
	};

        bless $self, $class;

        my $keys = { @_ };

	$self->{beginSignature} = "-----BEGIN PKCS7-----";
        $self->{endSignature}   = "-----END PKCS7-----";

        $self->{backend}   = $keys->{SHELL};
        $self->{dbDir}     = $keys->{DB_DIR};

        return if ((not $self->{backend}) or (not $self->{dbDir}));

	$self->{dBs}->{CERTIFICATE}->{FILE}	= "certificates";
	$self->{dBs}->{CERTIFICATE}->{INFO}	= "certificates_info";
	$self->{dBs}->{VALID_CERTIFICATE}	= "valid_certs";
	$self->{dBs}->{REVOKED_CERTIFICATE}	= "revoked_certs";
	$self->{dBs}->{SUSPENDED_CERTIFICATE}	= "suspended_certs";
	$self->{dBs}->{EXPIRED_CERTIFICATE}	= "expired_certs";

	$self->{dBs}->{REQUEST}->{FILE}		= "requests";
	$self->{dBs}->{REQUEST}->{INFO}		= "requests_info";
	$self->{dBs}->{PENDING_REQUEST}		= "pending_requests";
	$self->{dBs}->{DELETED_REQUEST}		= "deleted_requests";
	$self->{dBs}->{APPROVED_REQUEST}	= "approved_requests";
	$self->{dBs}->{ARCHIVIED_REQUEST}	= "archivied_requests";
	$self->{dBs}->{REVOKE_REQUEST}		= "revoke_requests";
	$self->{dBs}->{RENEW_REQUEST}		= "renew_requests";

        $self->{dBs}->{PENDING_CRR}             = "pending_crr";
        $self->{dBs}->{APPROVED_CRR}            = "approved_crr";
        $self->{dBs}->{ARCHIVIED_CRR}           = "archivied_crr";
        $self->{dBs}->{DELETED_CRR}             = "deleted_crr";

	$self->{dBs}->{CRL}->{FILE}		= "crl";
	$self->{dBs}->{CRL}->{INFO}		= "crl_info";
	$self->{dBs}->{VALID_CRL}		= "valid_crl";
	$self->{dBs}->{EXPIRED_CRL}		= "expired_crl";

	$self->{dBs}->{CA_CERTIFICATE}->{FILE}	= "ca_certificates";
	$self->{dBs}->{CA_CERTIFICATE}->{INFO}	= "ca_certificates_info";
	$self->{dBs}->{VALID_CA_CERTIFICATE} 	= "valid_ca_certificates";
	$self->{dBs}->{EXPIRED_CA_CERTIFICATE} 	= "expired_ca_certificates";

	$self->{dBs}->{SEARCH}->{PENDING_REQUEST}  = "pending_requests_search";
	$self->{dBs}->{SEARCH}->{APPROVED_REQUEST} = "approved_requests_search";
	$self->{dBs}->{SEARCH}->{DELETED_REQUEST}  = "deleted_requests_search";
	$self->{dBs}->{SEARCH}->{ARCHIVIED_REQUEST}= "archivied_requests_search";
	$self->{dBs}->{SEARCH}->{PENDING_CRR}   = "pending_crr_search";
	$self->{dBs}->{SEARCH}->{APPROVED_CRR}  = "approved_crr_search";
	$self->{dBs}->{SEARCH}->{ARCHIVIED_CRR} = "archivied_crr_search";
	$self->{dBs}->{SEARCH}->{DELETED_CRR}   = "deleted_crr_search";

	$self->{dBs}->{SEARCH}->{VALID_CERTIFICATE}     ="valid_certs_search";
	$self->{dBs}->{SEARCH}->{EXPIRED_CERTIFICATE}   ="expired_certs_search";
	$self->{dBs}->{SEARCH}->{REVOKED_CERTIFICATE}   ="revoked_certs_search";
	$self->{dBs}->{SEARCH}->{SUSPENDED_CERTIFICATE} ="susp_certs_search";

	## Defaults storage format. This does not apply to SPKAC requests
	$self->{defStoredFormat} 		= "PEM";
	$self->{defOutFormat}    		= "PEM";
 	$self->{beginHeader} 			= "-----BEGIN HEADER-----";
 	$self->{endHeader} 			= "-----END HEADER-----";

	return if ( not $self->{tools} = new OpenCA::Tools());

	if( not ( opendir( DIR, $self->{dbDir} ))) {
		return;
	} else {
		closedir(DIR);
	};

	return $self;
}

sub deleteData {
	my $self = shift;
	my $keys = { @_ };

	my $fileName = $keys->{FILENAME};
	my $key      = $keys->{KEY};

	my %DB;

	return if ( (not $key) or (not $fileName) );
	dbmopen( %DB, $fileName, 0600 ) or return;
		delete $DB{$key};
	dbmclose( %DB );

	return 1;
}

sub saveData {
	my $self = shift;
	my $keys = { @_ };

	my $fileName = $keys->{FILENAME};
	my $data     = $keys->{DATA};
	my $key      = $keys->{KEY};

	my %DB;

	return if ( not $key );
	dbmopen( %DB, $fileName, 0600 ) or return;
		$DB{$key}=$data;
	dbmclose( %DB );

	return 1;
}

sub getData {
	my $self = shift;
	my $keys = { @_ };

	my $fileName = $keys->{FILENAME};
	my $key      = $keys->{KEY};

	my %DB;
	my $ret;

	dbmopen( %DB, $fileName, 0400 ) or return;
		$ret=$DB{$key};
	dbmclose( %DB );

	return $ret;
}

sub getIndex {
	my $self  = shift;

	return $self->getHash( KEY=>"IDX", @_ );
}

sub getHash {
	my $self  = shift;
	my $keys = { @_ };

	my $fileName 	= $keys->{FILENAME};
	my $key		= $keys->{KEY};

	my ( $ret, $rec );
	
	$rec = $self->getData( FILENAME=>$fileName, KEY=>$key );
	$ret = $self->txt2hash( TXT=>$rec );

	return $ret;
}

sub saveIndex {
	my $self = shift;

	return $self->saveHash( KEY=>"IDX", @_ );
}

sub saveHash {
	my $self  = shift;
	my $keys = { @_ };

	my $fileName	 = $keys->{FILENAME};
	my $hash	 = $keys->{IDX};
	my $key 	 = $keys->{KEY};

	my $data =  $self->hash2txt( HASH=>$hash );

	return $self->saveData(FILENAME=>$fileName, KEY=>$key, DATA=>$data);
}

sub hash2txt {
	my $self  = shift;

	my $keys = { @_ };

	my $hash	= $keys->{HASH};

	my $record = "";
	my ( $i, $key, $val );

	while( ($key, $val ) = each %$hash ) {
		$record .= "$key=$val\n";
	}
	$record =~ s/(\n)$//;

	return $record;
}

sub txt2hash {
	my $self = shift;
	my $keys = { @_ };

	my $record 	= $keys->{TXT};

	my ( $ret, $key, $val, $line );

	foreach $line ( split ( /\n/, $record ) ) {
		$line =~ s/\s*=\s*/=/g;
		( $key, $val ) = ( $line =~ /(.*)\s*=\s*(.*)\s*/ );
		$ret->{$key} = $val;
	}
	return $ret;
}

sub deleteRecord {
	my $self = shift;
	my $keys = { @_ };

	my $fileName	= $keys->{FILENAME};
	my $dataType	= $keys->{DATATYPE};
	my $dbKey	= $keys->{KEY};
	my $mode	= $keys->{MODE};

	my ( $idx, $tmp );

	return if ( (not $dbKey) or ( not $fileName ) );

	if( $mode ne "RAW" ) {
		$idx = $self->getIndex( FILENAME=>$fileName );
		return if ( not $idx );
	}

	return if (not $self->deleteData( @_ ));

	$idx->{ELEMENTS}-- if ( $idx->{ELEMENTS} > 0 );
	$idx->{FIRST} = "0" if( not $idx->{FIRST} );

	if( $dbKey =~ /[a-zA-Z]+/ ) {
		$mode = "RAW";
		$idx->{LAST} = $idx->{ELEMENTS};
	}

	if( $mode ne "RAW" ) {
		if( $idx->{FIRST} == $dbKey ) {
			$tmp = ( $self->getNextItemKey( DATATYPE=>$dataType,
							KEY=>$dbKey ) or 0 );
			$idx->{FIRST} =  $tmp;
		}

		if( $dbKey == $idx->{LAST} ) {
			$tmp = ( $self->getPrevItemKey( DATATYPE=>$dataType,
							KEY=>$dbKey ) or 0 );
			$idx->{LAST} = $tmp
		}
	}

	$idx->{DELETED}++;
	$idx->{LAST_UPDATED} =  $self->{tools}->getDate();

	return if ( not $self->saveIndex( IDX=>$idx, FILENAME=>$fileName ));

	return 1;
}


sub addRecord {

	## In the dbKey we find nothing if we are going to add
	## a new record and the digest if we are going to update
	## an old one.
	my $self = shift;
	my $keys = { @_ };

	my $fileName 	= $keys->{FILENAME};
	my $dbKey 	= $keys->{KEY};
	my $dbVal 	= $keys->{DATA};
	my $mode 	= $keys->{MODE};
	
	my ( $idx, $isCert);

	## print ":::: ADD MODE => $mode<BR>\n";
	## print ":::: FILENAME => $fileName<BR>\n";
	## print ":::: DBVAL => " . length ($dbVal ) . "<BR>\n";
	## print ":::: DBKEY => $dbKey<BR>\n";

	return if ( (not $dbVal) or  ( not $fileName ) or 
			(not $idx = $self->getIndex( FILENAME=>$fileName)) );

	if ( $mode eq "UPDATE" ) {
		return if not $dbKey;

		return if ( not $self->saveData( KEY=>$dbKey, MODE=>$mode,
					FILENAME=>$fileName, DATA=>$dbVal));

		## print ":::: RECORD UPDATED => $dbKey<BR>\n";
		return $dbKey;
	}

	if ( not $dbKey ) {
		return if( $self->getData(FILENAME=>$fileName, KEY=>$dbKey));
		$dbKey = $idx->{NEXT};

		$idx->{LAST} = $dbKey;
		$idx->{NEXT}++;

		push ( @_ , KEY=>$dbKey );
	} else {
		if ( $idx->{LAST} < $dbKey ) {
			$idx->{LAST} = $dbKey;
			$idx->{NEXT} = $dbKey + 1;
		}
	}

	return if ( not $self->saveData( KEY=>$dbKey, MODE=>$mode,
				FILENAME=>$fileName, DATA=>$dbVal ));

	$idx->{ELEMENTS}++;
	$idx->{LAST_UPDATED} =  $self->{tools}->getDate();
	$idx->{FIRST} = $dbKey if( ($dbKey < $idx->{FIRST}) or 
						( $idx->{FIRST} == 0) );
	
	return if ( not $self->saveIndex( IDX=>$idx, FILENAME=>$fileName ));

	## print ":::: RECORD SUCCESSFULLY ADDED!<BR>\n";
	return $dbKey;
}

sub updateRecord {
	my $self = shift;

	return $self->addRecord( MODE=>"UPDATE", @_ );

}

sub initDB {
	## Generate a new db File and initialize it allowing the
	## DB to keep track of the DB status

	## There is a special record keeping additional useful
	## Informations about DB, this is the IDX

	my $self = shift;
	my $keys = { @_ };

	my $mode     = $keys->{MODE};
	my @fileList = ();

	my ( $key, $pkey );

	for $key ( keys %{$self->{dBs}} ) {
		if( $self->{dBs}->{$key} =~ /HASH/ ) {
			for $pkey ( keys %{$self->{dBs}->{$key}} ) {
				push ( @fileList, 
					$self->{dBs}->{$key}->{$pkey});
			}
		} else {
			push ( @fileList, $self->{dBs}->{$key});
		}
	}

	if( $mode eq "FORCE" ) {
		return $self->createDB( $mode, @fileList );
	} else {
		return 1;
	}
}

sub createDB {
	my $self = shift;
	my $mode = shift;

	my @fileList = @_;

	my ( $index, $val, $key, %DB, $date, $fileName, $i );
	my $dbDir = $self->{dbDir};

	if ( not $self->{tools} ) {
		$self->{tools} = new OpenCA::Tools();
	}
	$date = $self->{tools}->getDate();

	foreach $val ( @fileList ) {
		$fileName = "$dbDir/$val";

		## Now we build the IDX object (that keeps track of the
		## db status)
		$index = {
			DELETED=> "0",
			ELEMENTS=> "0",
			NEXT=> "1",
			FIRST=> "0",
			LAST=> "0",
			STATUS=> "UPDATED",
			LAST_UPDATED=> $date,
			FILENAME=> $fileName };

		if( -e (glob "$fileName.*" )[0] ) {
			if( $mode eq "FORCE" ) {
				my @tmpNameList = glob "$fileName*.old";

				foreach $i ( @tmpNameList ) {
					unlink( "$i");
				}

				@tmpNameList = glob "$fileName.*";
				foreach $i ( @tmpNameList ) {
					$self->{tools}->moveFiles( SRC=>$i,
						   DEST=>"$i.old" );
				}
				## Let's save the new DB status to file
				$self->saveIndex( FILENAME=>$fileName,
								IDX=>$index );
			}
		} else {
			## Let's save the new DB status to file
			$self->saveIndex( FILENAME=>$fileName, IDX=>$index );
		}
	}

	return 1;
}

sub getReferences {
	my $self = shift;
	my $keys = { @_ };

	my $key 	= $keys->{KEY};
	my $fileName 	= $keys->{FILENAME};

	my ( %DB, $dbVal );
	my @ret = ();

	return if not ( $key or $fileName );
	dbmopen( %DB, "$fileName", 0400 ) or return ;
		$dbVal=$DB{$key};
	dbmclose( %DB );

	return if ( not $dbVal );
	@ret = split( /:/, $dbVal );

	return @ret;
}

sub getBaseType {
	my $self = shift;

	my $keys = { @_ };
	my $dataType = $keys->{DATATYPE};

	my $ret;

	     if ( $dataType =~ /CA_CERTIFICATE/ ) {
		$ret = "CA_CERTIFICATE";
	} elsif ( $dataType =~ /CERTIFICATE/ ) {
		$ret = "CERTIFICATE";
	} elsif ( $dataType =~ /CRL/ ) {
		$ret = "CRL";
	} elsif ( $dataType =~ /REQUEST/ ) {
		$ret = "REQUEST";
        } elsif ( $dataType =~ /CRR/ ) {
                $ret = "CRR";
	} else {
		## Unsupported DATATYPE
		return;
	}

	return $ret;
}

sub getSearchAttributes {
	my $self = shift;
	my $keys = { @_ };

	my $dataType     = $keys->{DATATYPE};
	my @ret = ();
	my $baseType;

	return if ( not $dataType );

	$baseType = $self->getBaseType( DATATYPE => $keys->{DATATYPE} );

	if ( $baseType =~ /REQUEST/ ) {
		if( $dataType =~ /PENDING/ ) {
			@ret = ( "DN", "CN", "EMAIL", "RA" );
		} elsif ( $dataType =~ /APPROVED/ ) {
			@ret = ( "DN", "CN", "EMAIL", "OPERATOR" );
		} elsif ( $dataType =~ /REVOKE/ ) {
			@ret = ( "DN", "CN", "EMAIL", "REVOKE" );
		} else {
			@ret = ( "DN", "CN", "EMAIL" );
		}
        } elsif ( $baseType =~ /CRR/ ) {
		if( $dataType =~ /PENDING/ ) {
			@ret = ( "CERTIFICATE_SERIAL", "DN", "CN", "EMAIL",
				 "RA" );
		} elsif ( $dataType =~ /APPROVED/ ) {
			@ret = ( "CERTIFICATE_SERIAL", "DN", "CN", "EMAIL",
				 "OPERATOR", "RA" );
		} else {
			@ret = ( "CERTIFICATE_SERIAL", "DN", "CN", "EMAIL" );
		}
	} elsif ( $baseType =~ /CA_CERTIFICATE/ ) {
		@ret = ( "DN", "O", "CN", "EMAIL" );
	} elsif ( $baseType =~ /CERTIFICATE/ ) {
		@ret = ( "SERIAL", "DN", "CN", "EMAIL" );
	};

	return @ret;
}

sub storeItem {

	## Store a provided Item (DATA) provided the exact
	## DATATYPE. KEY (position in dB) data to match will
	## be automatically chosen on a DATATYPE basis.

	## The INFORM is used to get the data input format
	## PEM|DER|NET|SPKAC

	my $self = shift;
	my $keys = { @_ };

	my $dataType 	= $keys->{DATATYPE};	
	my $inform	= ( $keys->{INFORM} or "PEM" );

	my $object	= $keys->{OBJECT};	## an OpenCA::xxxx object
	my $mode	= $keys->{MODE};	## ACTUALLY only UPDATE|NULL

	my %DB;

	my ( @exts, @attributes );
	my ( $converted, $baseType, $fileName, $headFileName, $hashFileName,
	     $attr, $header, $dbKey, $digest );

	## Shall we give the ability to choose directly the
	## key ??? This is actually left out to provide a
	## very independent interface class... (huh?)
	my $serial	= $keys->{KEY};

	return if ( ($mode eq "UPDATE" ) and (not $serial));

	## dbKey will differ from serial only for certificates because
	## we store them by DECIMALs and not by HEX values.
	if( $self->isCertDataType( DATATYPE=>$dataType )) {
		## If a certificate is given then the key is
		## the DECIMAL value of the Cert's serial
		$dbKey = hex($object->getParsed()->{SERIAL});
	} else {
		$dbKey = $serial;
	}

	## print ":::: (storeItem) DEBUG => #1<BR>\n";
	## print ":::: (storeItem) DATATYPE => $dataType<BR>\n";
	## print ":::: (storeItem) OBJECT => $object<BR>\n";

	## if we have no db for that DATATYPE or no data then return
	return if ((not $object) or (not exists $self->{dBs}->{$dataType}));
	## print ":::: (storeItem) DEBUG => #2<BR>\n";

	## Here we define the base type to decide where to store the
	## passed data
	return if (not $baseType = $self->getBaseType(DATATYPE=>$dataType));


	## If the data is convertible, let's have only one internal
	## format to handle with
	## print "::: TYPE => ".$object->getParsed()->{HEADER}->{TYPE}."<BR>\n";
	if( $object->getParsed()->{HEADER}->{TYPE} !~ /(PKCS#10|IE)/ ) {
	 	$converted = $object->getParsed()->{ITEM};
	} else {
		if( $self->{defStoredFormat} eq "PEM" ) {
			$converted = $object->getPEM();
		} elsif ( $self->{defStoredFormat} eq "DER" ) {
			$converted = $object->getDER();
		} else {
			$converted = $object->getParsed()->{ITEM};
		}
		$converted .= $object->getParsed()->{SIGNATURE};
	}

	$converted = $self->getBody( $converted );

	## Now we have BASIC and EXTENDED DATATYPE, we store the data
	## into the basic dB
	$fileName = "$self->{dbDir}/$self->{dBs}->{$baseType}->{FILE}";
	$headFileName = "$self->{dbDir}/$self->{dBs}->{$baseType}->{INFO}";

	if( $dataType =~ /CERTIFICATE/ ) {
		$digest= $object->getParsed()->{HASH};
	} else {
		$digest= $self->{backend}->getDigest( DATA=> $converted . $$ );
	}
	if( $mode eq "UPDATE" ) {
		## print ":::: DELETING OLD ITEM => $serial<BR>\n";
		return if ( not $self->deleteItem( DATATYPE=>$dataType,
							KEY=>$serial ));
	}

	## If we are adding a duplicate of the certificate we should
	## at least delete the old value or update it's contents. The
	## safest way is to delete the old one and then write in a new
	## one...
	if( ($dataType =~ /CERTIFICATE/) and ($mode ne "UPDATE" ) and
			($self->getData( FILENAME=>$fileName, KEY=>$digest) )) {
		## Data Already exists in database, this should not happen
		## if datatype is CERTIFICATE, we assume it is an error, here
		## (if not an update... )
		return (-1);
	}

	## We add the record and update the IDX one calling the addRecord()
	## print ":::: (storeItem) ADDING RECORD => $digest<BR>\n";
	return if ( not $self->addRecord( FILENAME=>$fileName,
			KEY=>$digest, DATA=>$converted ));
	## print ":::: (storeItem) ADDED RECORD => $digest<BR>\n";

	## Let's update the INFO value
	## print ":::: (storeItem) HEADER => $digest ($headFileName)<BR>\n";
	if( exists $object->getParsed()->{HEADER} ) {
		return if( not $self->saveHash( FILENAME=>$headFileName,
			KEY=>$digest, IDX=>$object->getParsed()->{HEADER} ));
	}
	## print ":::: (storeItem) HEADER => DONE<BR>\n";

	## Now add the couple SERIAL=HASH to the appropriate DATATYPE dB
	## We get the serial (that identifies the object when searching or
	if( $baseType eq $dataType ) {
		$dataType = "VALID_" . $dataType;
	}

	$hashFileName = "$self->{dbDir}/$self->{dBs}->{$dataType}";
	if( $mode eq "UPDATE" ) {
		## print ":::: UPDATING ITEM => $serial<BR>\n";
		return if ( not $serial = 
			$self->addRecord( FILENAME => $hashFileName,
					KEY=>$dbKey, DATA=>$digest));
	} else {
		return if ( not $serial = 
			$self->addRecord( FILENAME => $hashFileName,
				KEY=>$dbKey, DATA=>$digest));
	}

	## Let's add extra searching path... the attr list will be stored
	## into the search dB.
	## we expect a great number of requests archivied/processed by the
	## same RA or OPERATOR ( for example ), we'll see later...
	@attributes = $self->getSearchAttributes( DATATYPE=>$dataType );

	## Get the new filename to use from the search subsection
	$fileName = "$self->{dbDir}/$self->{dBs}->{SEARCH}->{$dataType}";

	for $attr ( @attributes ) {
		my ( $key, $list, $attrVal );

		if( $attr =~ /(RA|TYPE)/i ) {
			$attrVal = $object->getParsed()->{HEADER}->{$attr};
		} else {
			$attrVal = $object->getParsed()->{$attr};
		}
		## print "::: PARSED ATTRIBUTE $attr => " .
				$object->getParsed()->{$attr} ."<BR>\n";
		## print "::: ADDING ATTRIBUTE $attr => $attrVal<BR>\n";

		next if ( (not $attrVal) or ($attrVal eq "" ) or 
							($attrVal eq "n/a"));
	
		$key = "$attr:$attrVal";
		$list = $self->getData( FILENAME=>$fileName, KEY=>$key );

		## Is it really needed the control on the existance of the
		## $list variable ???
		if( ( not $list ) or ( not $list =~ /\:$serial/ )) {
			## We add here the serial it has in the
			## {$dataType} dB
			$list .= ":$serial";

			next if ( not $self->saveData( FILENAME=>$fileName,
						KEY=>$key, DATA=>$list) );
		}
	}

	## Now we should set all the extra variables to the search
	## facilities
	## print ":::: (storeItem) DONE => OK.<BR>\n";
	return $serial;
}

## sub exists {
## 	## Returns True (dbKey) if the key exists in dB, else
## 	## it will return NULL False (null);
## 
## 	my $self = shift;
## 	my $keys = { @_ };
## 
## 	my ( $ret, $hash, $fileName, $item, $hash );
## 
## 	my $type   	= $keys->{DATATYPE};
## 	my $baseType	= $self->getBaseType( DATATYPE=>$type );
## 	my $dbKey    	= $keys->{KEY};
## 
## 	$dbKey = hex ( $dbKey ) if( $self->isCertDataType( DATATYPE=>$type ));
## 	$ret   = $self->existDB( DATATYPE=> $type, KEY=>$dbKey );
## 
## 	return $dbKey;
## }

sub existsDB {
	## Returns True (dbKey) if the key exists in dB, else
	## it will return NULL False (null);

	my $self = shift;
	my $keys = { @_ };

	my ( $hash, $fileName, $item, $hash );

	my $type   	= $keys->{DATATYPE};
	my $baseType	= $self->getBaseType( DATATYPE=>$type );
	my $dbKey    	= $keys->{KEY};

	$type = "VALID_" . $type if( $baseType eq $type );

	$fileName = "$self->{dbDir}/$self->{dBs}->{$type}";
	return if ( (not $fileName) or ( $fileName =~ /HASH/ ) or
						(not $dbKey) or (not $type));

	$hash = $self->getData( FILENAME=>$fileName, KEY=>$dbKey);
	if( $hash ) {
		return $dbKey;
	} else {
		return;
	}
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

	my ( $fileName, $item, $txtItem, $body, $header, $hash, $tmpBody );

	my $type   	= $keys->{DATATYPE};
	my $baseType	= $self->getBaseType( DATATYPE=>$type );

	my $serial    	= $keys->{KEY};  ## Key passed when stored item
	my $mode   	= $keys->{MODE}; ## Actually only RAW or NULL

	if( $baseType eq $type ) {
		$type = "VALID_" . $type;
	}

	## Let's make some needed check
	$fileName = "$self->{dbDir}/$self->{dBs}->{$type}";

	return if ( (not $fileName) or ( $fileName =~ /HASH/ ) or
					(not $serial) or (not $type));

	## Now we get the HASH value, with this we get the corresponding
	## object
	if( $self->isCertDataType( DATATYPE=>$type) ) {
	 	## print "::: (getItem) SERIAL => $serial<BR>\n";
	 	$serial = hex ( $serial );
	 	## print "::: (getItem) REAL SERIAL => $serial<BR>\n";
	};

	return if ( not ( $hash = $self->getData( FILENAME=>$fileName,
					 KEY=>$serial )));
	## Here we get the txt object
	$fileName = "$self->{dbDir}/$self->{dBs}->{$baseType}->{FILE}";

	$body = $self->getData( FILENAME=>$fileName, KEY=>$hash );
	return if ( not $body );
	
	## Let's get the extra info in the HEADER section of the object
	$fileName = "$self->{dbDir}/$self->{dBs}->{$baseType}->{INFO}";
	$header = $self->getData( FILENAME=>$fileName, KEY=>$hash );

	## We may want to convert to a default format all objects
	## excluding the "TXT" ones...
	if( $body !~ /SPKAC\s*=|RENEW\s*=|REVOKE\s*=/ ) {
		$tmpBody = $self->{backend}->dataConvert( 
					 DATATYPE=>$baseType,
					 INFORM=> $self->{defStoredFormat},
					 OUTFORM=> $self->{defOutFormat},
					 DATA=> $body );

		$body = $tmpBody . $self->getSignature( $body );
	}
	
	## This $txtItem have the original object as it was stored
	## with all infos in it
	$txtItem = $self->{beginHeader} . "\n" . $header . "\n" .
				$self->{endHeader} . "\n" . $body ;
	## $txtItem = $body;

	## If it was asked only the text version, we send out only that
	## without generating an OBJECT from it
	if( $mode eq "RAW" ) {
		return $txtItem;
	}

	## Build an Object from retrieved DATA
	if( $baseType =~ /CERTIFICATE/ ) {
		$item = new OpenCA::X509( SHELL=>$self->{backend},
			 	          INFORM=>$self->{defOutFormat},
			        	  DATA=>$txtItem );
	} elsif ( $baseType =~ /CRL/ ) {
		$item = new OpenCA::CRL( SHELL=>$self->{backend},
			        	 INFORM=>$self->{defOutFormat},
			        	 DATA=>$txtItem );
	} elsif ( $baseType =~ /CRR/ ) {
		$item = new OpenCA::CRR( SHELL=>$self->{backend},
			        	 DATA=>$txtItem );
	} elsif ( $baseType =~ /REQUEST/ ) {
		my $format = $self->{defOutFormat};

		if( $txtItem =~ /SPKAC\s*=|RENEW\s*=|REVOKE\s*=/ ) {
			( $format ) = ( $txtItem =~ /(SPKAC|RENEW|REVOKE)/ );
		}

		$item = new OpenCA::REQ( SHELL=>$self->{backend},
			        	 INFORM=>$format,
			        	 DATA=>$txtItem );
	} else {
		## if we cannot build the object there is probably
		## an error, retrun a void ...
		return;
	}

	if( $self->isCertDataType( DATATYPE=>$type) ) {
		$item->{parsedItem}->{DBKEY} = sprintf( "%lx",$serial);
	} else {
		$item->{parsedItem}->{DBKEY} = $serial;
	}


	## We return the object
	return $item;

}

sub getNextItem {
	## Get Next Item given a serial number

	my $self = shift;
	my $keys = { @_ };

	my $key 	= (($keys->{KEY}) or (-1));
	my $dataType 	= $keys->{DATATYPE};
	my $mode 	= $keys->{MODE};

	my ( $idx, $fileName, $dbKey, $item );

	## Return NULL if we don't get Next Item Key
	return if( not $dbKey = $self->getNextItemKey( @_ ));

	## Return dbKey if we have a RAW request
	return $dbKey if( $mode eq "RAW" );

	## Return object (if any)
	return $self->getItem( DATATYPE=>$dataType, MODE=>$mode,KEY=>$dbKey);
}

sub getPrevItem {
	## Get Prev Item given a serial number

	my $self = shift;
	my $keys = { @_ };

	my $key 	= $keys->{KEY};
	my $dataType 	= $keys->{DATATYPE};
	my $mode 	= $keys->{MODE};

	my ( $idx, $fileName, $dbKey, $item );

	## Let's get prev id
	return if( not $dbKey = $self->getPrevItemKey( @_ ));

	return $dbKey if( $mode eq "RAW" );

	## Return item
	return $self->getItem(DATATYPE=>$dataType, MODE=>$mode, KEY=>$dbKey);
}

sub getNextItemKey {
	## Get Next Item given a serial number

	my $self = shift;
	my $keys = { @_ };

	my $key 	= $keys->{KEY};
	my $dataType 	= $keys->{DATATYPE};

	my ( $idx, $fileName, $item, $isCert );

	## print "::: (getNextItemKey) PASSED KEY => $key<BR>\n";
	## print "::: (getNextItemKey) PASSED DATATYPE => $dataType<BR>\n";

	return if (not $dataType);

	$fileName = "$self->{dbDir}/$self->{dBs}->{$dataType}";
	return if (not $idx = $self->getIndex( DATATYPE=>"$dataType",
						FILENAME=>"$fileName" ));

	## If it is a CERT dataType, we want the DECIMAL value
	$key = hex( $key ) if($self->isCertDataType( DATATYPE=>$dataType ));

	if( not $key ) {
		$key = $idx->{FIRST};

		if( $self->isCertDataType( DATATYPE=>$dataType )) {
			$key = sprintf( "%lx", $key);
		}

		## print "::: (getNextItemKey) No Key Given => Returning $key<BR>\n";

		return $key;
	}

	while( $key <= $idx->{LAST} ) {
		$key++;

		## print "::: (getNextItemKey) CURRENT KEY => $key<BR>\n";
		last if($self->existsDB(DATATYPE=>"$dataType", KEY=>$key));
	}

	if( $key <= $idx->{LAST} ) {
		if( $self->isCertDataType( DATATYPE=>$dataType) ) {
			return sprintf("%lx", $key);
		}

		return $key;
	} else {
		## print "::: (getNextItemKey) NO KEY FOUND => $key (LAST " . 
							$idx->{LAST} . "<BR>\n";
		return;
	}
}

sub getPrevItemKey {
	## Get Prev Item Key

	my $self = shift;
	my $keys = { @_ };

	my $key 	= $keys->{KEY};
	my $dataType 	= $keys->{DATATYPE};

	my ( $idx, $fileName, $item );

	$fileName = "$self->{dbDir}/$self->{dBs}->{$dataType}";
	return if (not $idx = $self->getIndex( DATATYPE=>$dataType,
						FILENAME=>$fileName ));

	## print "::: (getPrevItemKey) ORIG KEY => $key<BR>\n";

	if( not $key ) {
		$key = $idx->{FIRST};

		if( $self->isCertDataType( DATATYPE=>$dataType )) {
			$key = sprintf( "%lx", $key);
		}

		return $key;
	}

	## If it is a CERT dataType, we want the DECIMAL value
	$key = hex( $key ) if($self->isCertDataType( DATATYPE=>$dataType ));

	while( $key > 0 ) {
		$key--;
		last if( $self->existsDB( DATATYPE=>$dataType, KEY=>$key ));
	}

	if( $key > 0 ) {
		## We return HEX value if a Cert dataType is passed
		if($self->isCertDataType(DATATYPE=>$dataType)) {
			return sprintf("%lx",$key);
		}

		return $key;
	} else {
		return;
	}
}

sub getFirstItemKey {
	## Get First Item Key a serial number

	my $self = shift;
	my $keys = { @_ };

	my $dataType 	= $keys->{DATATYPE};

	my ( $idx, $fileName, $key );

	$fileName = "$self->{dbDir}/$self->{dBs}->{$dataType}";
	return if (not $idx = $self->getIndex( DATATYPE=>$dataType,
						FILENAME=>$fileName ));

	$key = $idx->{FIRST};

	if( $key == -1 ) {
		return;
	} else {
		$key = sprintf("%lx",$key) if($self->isCertDataType($keys));
		return $key;
	}
}

sub deleteItem {

	## Store a provided Item (DATA) provided the exact
	## DATATYPE. KEY (position in dB) data to match will
	## be automatically chosen on a DATATYPE basis.

	## The INFORM is used to get the data input format
	## PEM|DER|NET|SPKAC

	my $self = shift;
	my $keys = { @_ };

	my $type       = $keys->{DATATYPE};
	my $key        = $keys->{KEY};

	my ( $fileName, $baseType, $hash, $i, $sKey, $sVal, $item );

	return if ( (not $key ) or ( not exists $self->{dBs}->{$type}) );

	my $baseType = $self->getBaseType( DATATYPE=>$type );

	if( not $item = $self->getItem( DATATYPE=>$type, KEY=>$key )) {
		return;
	}

	## If it is a CERT dataType, we want the DECIMAL value
	if( $self->isCertDataType( DATATYPE=>$type )) {
		$key = hex($key);
	}

	$fileName = "$self->{dbDir}/$self->{dBs}->{$type}";
	return if(not $hash = 
		$self->getData(FILENAME=>$fileName,KEY=>$key));

	$fileName = "$self->{dbDir}/$self->{dBs}->{SEARCH}->{$type}";

	## print "::: DEBUG => SEARCHING ATTRIBUTES<BR>\n";
	for $i ( $self->getSearchAttributes( DATATYPE=>$type ) ) {
		$sKey = "$i:" . ( $item->getParsed()->{$i} or
			$item->getParsed()->{HEADER}->{$i} );

		## print "::: ITEM HASH => $sKey ($i)<BR>\n";
		next if ( not $sVal = $self->getData( FILENAME=>$fileName,
							KEY=>$sKey ));

		## print "::: ITEM HASH VAL => $sVal<BR>\n";
		$sVal =~ s/\:$key//;
		## print "::: NEW ITEM HASH VAL => $sVal<BR>\n";

		if( length( $sVal ) < 2 ) {
			$self->deleteRecord(FILENAME=>$fileName, KEY=>$sKey,
					DATATYPE=>$type, MODE=>"RAW" );
			## print "::::: ERASED RECORD $sKey!<BR>\n";
		} else {
			return if ( not $self->saveData( FILENAME=>$fileName,
						KEY=>$sKey, DATA=>$sVal ));
		}
	}

	$fileName = "$self->{dbDir}/$self->{dBs}->{$baseType}->{FILE}";
	## print "::: DELETING $hash ($fileName).\n";
	return if ( not $self->deleteRecord(FILENAME=>$fileName, 
				DATATYPE=>$type, KEY=>$hash ));

	$fileName = "$self->{dbDir}/$self->{dBs}->{$type}";
	## print "::: DELETING $key ($fileName) $type.\n";
	return if ( not $self->deleteRecord(FILENAME=>$fileName,
					DATATYPE=>$type, KEY=>$key ));

	return 1;
}

sub updateStatus {

	## Updates the status of an element, in DBMS actually
	## moving data to the new "status" DB (i.e. EXPIRED,
	## REVOKED, etc... )

	my $self = shift;
	my $keys = { @_ };

	my $item    = $keys->{OBJECT};
	my $oldType = $keys->{DATATYPE};
	my $newType = $keys->{NEWTYPE};

	return if ( not exists $self->{dBs}->{$newType} );
	return if ( not $self->deleteItem( DATATYPE=>$oldType,
					KEY=>$item->getParsed()->{DBKEY} ));

	## print "::: OBJECT => DELETED SUCCESSFULLY<BR>\n";
	return if (not $self->storeItem(DATATYPE=>$newType, OBJECT=>$item));
	## print "::: OBJECT => ADDEDD SUCCESSFULLY<BR>\n";

	return 1;
}

sub elements {

	## Returns number of elements contained in a dB. This number
	## is stored in the ELEMENTS key and it is updated each time
	## the dB module operates on the db.

	my $self = shift;
	my $keys = { @_ };

	my $type = $keys->{DATATYPE};

	my $ret = 0;
	my $fileName;

	return if ( not exists $self->{dBs}->{$type} );
	$fileName = "$self->{dbDir}/$self->{dBs}->{$type}";

	$ret = $self->getIndex( FILENAME=>$fileName );

	return $ret->{ELEMENTS};
}

sub rows {

	## Returns the number of item matching the request. You can search
	## for generic DATATYPE such as CERTIFICATE|REQUEST|CRL
	## or restricted type (EXPIRED_CERTIFICATE|REVOKED_CERTIFICATE|
	## VALID_CERTIFICATE...
	##
	## This func should be used in conjunction with searching function
	## use the elements sub instead if you wish to know how many specific
	## dB elements are there (such as VALID_CERTIFICATES, etc ... )

	my $self = shift;
	my $keys = { @_ };

	return $self->searchItems( MODE=>"ROWS", @_ );
}

sub searchItems {

	## Returns the requested item LIST. You can search for
	## generic DATATYPE such as CERTIFICATE|REQUEST|CRL
	## or restricted type (EXPIRED_CERTIFICATE|REVOKED_CERTIFICATE|
	## VALID_CERTIFICATE...

	my $self = shift;
	my $keys = { @_ };

	my @retList  = ();
	my ( $dataType, $tmp, $count );

	my $type     = $keys->{DATATYPE};
	my $mode     = $keys->{MODE};

        my $baseType = $self->getBaseType( DATATYPE=>$dataType );

	$type = "VALID_$type" if( $type eq $baseType );

	## We remove the old value, we want to pass it by hand to the
	## searchDB function
	delete ( $keys->{DATATYPE} );

	## Check if some attributes are to be searched or if it is
	## a simple listItems request like... count == 0 means listItems...
	$count = 0;
	foreach $tmp ( keys %$keys ) {
		next if ( $tmp =~ /ITEMS/i );
		next if ( $tmp =~ /FROM/i );
		next if ( $tmp =~ /TO/i );
		next if ( $tmp =~ /MODE/i );
		$count++;
	}

	foreach $dataType ( keys %{$self->{dBs}} ) {
		next if (($dataType =~ /HASH/) or ($dataType eq $baseType));

		if ( $dataType =~ /$type/i ) {
			my @plist;

			$keys->{DATATYPE} = $dataType;

			if( $count == 0 ) {
				@plist = $self->listItems( DATATYPE=>$dataType,
								MODE=>$mode )
			} else {
				@plist = $self->searchItemDB( $keys );
			}

			push ( @retList, @plist );
		}
	}

	if( $mode eq "ROWS" ) {
		return $#retList + 1;
	} else {
		return @retList;
	}
}

sub searchItemDB {
	my $self = shift;
	my $keys = shift;

	## Get the dataType
	my $dataType 	= $keys->{DATATYPE};
	my $mode	= $keys->{MODE};
	my $maxItems 	= $keys->{ITEMS};
	my $from     	= ( $keys->{FROM} or 0 );

	my ( $fileName, $txtList, $key, $dbVal, $dbKey, $ret, $i );

	my @retList 	= ();
	my @objRetList	= ();
	my $retNum 	= 0;

	## We delete the not needed keys
	delete( $keys->{DATATYPE} );
	delete( $keys->{MODE} );
	delete( $keys->{ITEMS} );
	delete( $keys->{FROM} );

	## print "::: DATATYPE => $dataType<BR>\n";
	return if ( not exists $self->{dBs}->{SEARCH}->{$dataType});
	## print "::: SEARCH => $dataType<BR>\n";

	## Let's Build the SEARCH dB fileName
	$fileName = "$self->{dbDir}/$self->{dBs}->{SEARCH}->{$dataType}";

	## For every keyword let's get the list of values
	while( ($dbKey, $dbVal) = each %$keys ) {
		$key = "$dbKey:$dbVal";

		## print "::: GETTING KEY => $key<BR>\n";
		## print "::: FILENAME $dataType => $fileName<BR>\n";
		$txtList->{$dbKey} = 
			$self->getData( FILENAME=>$fileName, KEY=>$key );
	}

	## We want to eliminate any reference to serials who don't have
	## all the fields required, here we buld a list with number of
	## time a serial appear
	$i = 0;
	foreach $key ( keys %$txtList ) {
		my ( @tmp, $tmpSer );

	 	## Here we have the number of fields checked, a serial
		## should be present each time into the final record;
		$i++;

		@tmp = grep( /\S+/ , split( /\:/, $txtList->{$key} ));
		for $tmpSer ( @tmp ) {
			$ret->{$tmpSer}++;
		}
	}

	## Now we delete the serials who don't appear in all searching
	## Results
	foreach $key ( keys %$ret ) {
		delete $ret->{$key} if( $ret->{$key} < $i );
		if( exists $ret->{$key} ) {
			push ( @retList, $key );
			## print "::: ADDED TO RETLIST $key => " .
		## 				$ret->{KEY} . "<BR>\n";
		}
	}

	return @retList if( $mode eq "ROWS" );
	
	for $i (@retList) {
		my $obj;

		next if ( $retNum < $from );
		last if ( ( $maxItems ) and ( $retNum > $maxItems) );

		## print ":::: (searchItemDB) ADDING => $i<BR>\n";
		next if ( not $obj = $self->getItem( DATATYPE=>$dataType,
							KEY=>$i ));

	        ## Check for data consistent (VALID vs EXPIRED)
	        if( ($dataType =~ /VALID_CERTIFICATE/i ) and
                        ( $self->{tools}->cmpDate(
                                DATE_1=>$self->{tools}->getDate(),
                                DATE_2=>$obj->getParsed()->{NOTAFTER})>0) ) {
                	$self->updateStatus( OBJECT=>$obj,
                                        DATATYPE=>$dataType,
                                        NEWTYPE=>"EXPIRED_CERTIFICATE");
                	next;
        	}
        	if( ($dataType =~ /VALID_CRL/i ) and
                        ( $self->{tools}->cmpDate(
                                DATE_1=>$self->{tools}->getDate(),
                                DATE_2=>$obj->getParsed()->{NEXT_UPDATE})>0)){

                	$self->updateStatus( OBJECT=>$obj, 
					DATATYPE=>$dataType,
                                        NEWTYPE=>"EXPIRED_CRL");
                	next;
        	}

		$obj->{DATATYPE} = $dataType;
		## print ":::: (searchItemDB) ADDED => $obj<BR>\n";
		push( @objRetList, $obj );

		$retNum++;
	}

	## print ":::: (searchItemDB) RETNUM => $retNum ( $#retList )<BR>\n";
	## print ":::: (searchItemDB) FROM => $from <BR>\n";
	## print ":::: (searchItemDB) MAXITEMS => $maxItems <BR>\n";

	return @objRetList;
}

sub listItems {
	my $self = shift;
	my $keys = { @_ };

	my $dataType	= $keys->{DATATYPE};
	my $elements 	= $self->elements( DATATYPE=>$dataType );
	my $from 	= ( $keys->{FROM} or 0 );
	my $maxItems	= $keys->{ITEMS};
	my $mode	= $keys->{MODE};

	my ( @ret, $baseType, $retItems, $i, $item, $dbKey );

	return if( not $dataType );

	$baseType = $self->getBaseType( DATATYPE=>$dataType );
	$dataType = "VALID_" . $dataType if( $dataType eq $baseType ); 

	## if( (not $from) or 
	## 	($self->getFirstItemKey(DATATYPE=>"$dataType")>$from)){
	## 	    $dbKey = $self->getFirstItemKey(DATATYPE=>"$dataType");
	##  } else {
	## 	$dbKey = $self->getPrevItemKey(DATATYPE=>"$dataType",
	## 					KEY=>"$from");
	## }

	if( ($maxItems) and ($maxItems < $elements)) {
		$retItems = $maxItems;
	} else {
		$retItems = $elements;
	}

	## print "::: (listItems) FROM  => $dbKey<BR>\n";
	## print "::: (listItems) MAX ITEMS => $maxItems<BR>\n";
	## print "::: (listItems) RET ITEMS => $retItems<BR>\n";
	## print "::: (listItems) INIT KEY => $dbKey<BR>\n";

	for ( $i = 0; $i <= $retItems; $i++ ) {
		## print "::: (listItems) i => $i<BR>\n";
		last if ( not $dbKey = 
			$self->getNextItemKey(DATATYPE=>$dataType,
							KEY=>$dbKey));

		## print "::: (listItems) dbKey => $dbKey<BR>\n";
		if( $mode eq "RAW" ) {
			push ( @ret, $dbKey );
		} else {
			$item = $self->getItem( DATATYPE=>$dataType,
						  KEY=>$dbKey );

			## Check for data consistent (VALID vs EXPIRED)
			if( ($dataType =~ /VALID_CERTIFICATE/i ) and
				( $self->{tools}->cmpDate( 
					DATE_1=>$self->{tools}->getDate(),
					DATE_2=>$item->getParsed()->{NOTAFTER})>0) ) {
				$self->updateStatus( OBJECT=>$item,
						DATATYPE=>$dataType,
						NEWTYPE=>"EXPIRED_CERTIFICATE");
				return;
			}
			if( ($dataType =~ /VALID_CRL/i ) and
				( $self->{tools}->cmpDate( 
					DATE_1=>$self->{tools}->getDate(),
					DATE_2=>$item->getParsed()->{NEXT_UPDATE})>0)){

				$self->updateStatus( OBJECT=>$item,
						DATATYPE=>$dataType,
						NEWTYPE=>"EXPIRED_CRL");
					return;
			}
			push( @ret, $item ) if( $item );
		}
		## print "::: (listItems) ret => $#ret<BR>\n";
	}

	return @ret;
}


sub isCertDataType {
	my $self = shift;
	my $keys = { @_ };

	my $dataType = $keys->{DATATYPE};

	if ( $dataType =~ /^(VALID|REVOKED|EXPIRED)_CERTIFICATE/i ) {
		return 1;
	}

	return;
}


sub getSignature {
        my $self = shift;
        my $txt  = shift;

        my $ret;

        my $beginSig    = $self->{beginSignature};
        my $endSig      = $self->{endSignature};

        ## Let's get text between the two headers, included
        if( ($ret) = ( $txt =~ /($beginSig[\S\s\n]+$endSig)/m) ) {
                return $ret
        } else {
                return;
        }

        return $ret;
}

sub getBody {
        my $self = shift;

        my $ret = shift;

        my $beginHeader         = $self->{beginHeader};
        my $endHeader           = $self->{endHeader};

        ## Let's throw away text between the two headers, included
        $ret =~ s/($beginHeader[\S\s\n]+$endHeader\n)//;

        return $ret
}


sub toHex {
	my $self 	= shift;
	my $decimal 	= shift;
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

Here there is a list of the current available functions. Where there
is (*) mark, the function is to be considered private and not public.

	new {};
		build a new DB object;

	deleteData (*) {};
		delete data on a DBM file;

	saveData (*) {};
		save data on a DBM file;

	getData (*) {};
		retrieve data from a DBM file;

	getIndex {};
		retrieve the IDX from a DBM file;

	getHash (*) {};
		get data and put it into hash format (used for header
		extra info retrivial);

	saveIndex {};
		save the IDX to a DBM file;
	
	saveHash (*) {};
		save an HASH to a DBM file (in a single key);

	hash2txt (*) {};
		convert an HASH to a txt (VAR=VAL);

	txt2hash (*) {};
		convert a TEXT to an HASH (VAR=VAL);

	deleteRecord (*) {};
		delete an entry from the DB (and corresponding search
		dB);

	addRecord (*) {};
		add a record to a DB (and corresponding search dB);

	updateRecord (*) {};
		update a dB record;

	initDB {};
		initialize the dB structure and creates DBM files;

	createDB (*) {};
		create and initialize the DBM;

	getReferences {};

	getBaseType {};
		get Base datatye given a generic one ( i.e. from PENDING_
		REQUEST to REQUEST);

	getSearchAttributes (*) {};
		get a list of attributes for the search facility;

	storeItem {};
		store a given object (OpenCA::XXXX);

	getItem {};
		retrieve an object given the serial number;

	getNextItem {};
		get next object (or serial) given a serial;

	getPrevItem {};
		get previous object (or serial);

	getNextItemKey {};
		get Next Item dB Key;

	getPrevItemKey {};
		get previous Item dB Key;

	deleteItem {};
		delete an Item from the dB;

	elements {};
		returns number of elements of a given DATATYPE;

	rows {};
		return number of elements matching a serach;

	searchItems {};
		returns objects/serials matching the search on generic
		datatypes (i.e. CERTIFICATE, REQUEST);

	searchItemDB (*) {};
		returns objects/serials matching the search on exact
		datatypes (i.e. VALID_CERTIFICATE, PENDING_REQUEST);
		
	listItems {};
		get a listing of a specified datatype (or part of them);

	isCertDataType (*) {};
		returns true if the given datatype is a certificate
		related one;

	getSignature (*) {};
		get the signature (PKCS7) attached to an Item;

	getBody (*) {};
		get the body of an Item (without header or signature);

	toHex (*) {};
		convert a decimal to an hex;

=head1 AUTHOR

Massimiliano Pala <madwolf@openca.org>

=head1 SEE ALSO

OpenCA::OpenSSL, OpenCA::X509, OpenCA::CRL, OpenCA::REQ,
OpenCA::TRIStateCGI, OpenCA::Configuration, OpenCA::Tools

=cut
