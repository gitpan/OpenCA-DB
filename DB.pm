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

$OpenCA::DB::VERSION = '0.8.6a';

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
	$self->{dBs}->{APPROVED_REQUEST}	= "approved_requests";
	$self->{dBs}->{ARCHIVIED_REQUEST}	= "archivied_requests";

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
	$self->{dBs}->{SEARCH}->{ARCHIVIED_REQUEST}="archivied_requests_search";

	$self->{dBs}->{SEARCH}->{VALID_CERTIFICATE}     ="valid_certs_search";
	$self->{dBs}->{SEARCH}->{EXPIRED_CERTIFICATE}   ="expired_certs_search";
	$self->{dBs}->{SEARCH}->{REVOKED_CERTIFICATE}   ="revoked_certs_search";
	$self->{dBs}->{SEARCH}->{SUSPENDED_CERTIFICATE} ="susp_certs_search";

	## Defaults storage format. This does not apply to SPKAC requests
	$self->{defStoredFormat} 		= "DER";
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
	## tie ( %DB, "AnyDBM_File", "$fileName", O_CREAT|O_RDWR, 0600 );
	dbmopen( %DB, $fileName, 0600 ) or return;
		delete $DB{$key};
	dbmclose( %DB );
	##untie %DB;

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
	## tie ( %DB, "AnyDBM_File", "$fileName", O_CREAT|O_RDWR, 0600 );
	dbmopen( %DB, $fileName, 0600 ) or return;
		$DB{$key}=$data;
	dbmclose( %DB );
	##untie %DB;

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

	my $fileName = $keys->{FILENAME};
	my %DB;

	my ( $ret, $rec );
	
	$rec = $self->getData( FILENAME=>$fileName, KEY=>"IDX" );
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

	return $self->saveData( FILENAME=>$fileName, KEY=>$key, DATA=>$data );
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

	my $idx;

	return if ( (not $dbKey) or ( not $fileName ) );

	if( $mode ne "RAW" ) {
		$idx = $self->getIndex( FILENAME=>$fileName );
		return if ( not $idx );
	}

	return if ( not $self->deleteData( @_ ) );

	if( $mode ne "RAW" ) {
		my $prev = $self->getPrevItem( DATATYPE=>$dataType,
						MODE=>"RAW" );

		$idx->{ELEMENTS}-- 	if ( $idx->{ELEMENTS} > 0 );
		$idx->{FIRST}++ 	if( $idx->{FIRST} == $dbKey );

		$idx->{DELETED}++;
		$idx->{LAST_UPDATED} =  $self->{tools}->getDate();
		$idx->{NEXT} = $prev+1  if( $prev);
	}

	return if ( not $self->saveIndex( IDX=>$idx, FILENAME=>$fileName ));

	return 1;
}


sub addRecord {
	my $self = shift;
	my $keys = { @_ };

	my $fileName 	= $keys->{FILENAME};
	my $dbKey 	= $keys->{KEY};
	my $dbVal 	= $keys->{DATA};
	my $mode 	= $keys->{MODE};
	my $idx;

	return if ( (not $dbVal) or  ( not $fileName ) or
			(not $idx = $self->getIndex( FILENAME=>$fileName)) );

	if ( not $dbKey ) {

		$dbKey = $idx->{NEXT};
		$idx->{NEXT}++;

		push ( @_ , KEY=>$dbKey );
	}

	if( $mode ne "UPDATE" ) {
		return if( $self->getData( FILENAME=>$fileName, KEY=>$dbKey));

		return if ( not $self->saveData( KEY=>$dbKey, MODE=>$mode,
					FILENAME=>$fileName, DATA=>$dbVal ));

		$idx->{ELEMENTS}++;
		$idx->{LAST_UPDATED} =  $self->{tools}->getDate();
		$idx->{FIRST} = $dbKey if( $dbKey < $idx->{FIRST});
	} else {
		return if ( not $self->saveData( KEY=>$dbKey, MODE=>$mode,
					FILENAME=>$fileName, DATA=>$dbVal ) );
	}
	return if ( not $self->saveIndex( IDX=>$idx, FILENAME=>$fileName ));

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
	} else {
		## Unsupported DATATYPE
		return;
	}

	return $ret;
}

sub getSearchAttributes {
	my $self = shift;
	my $keys = { @_ };

	my $type = $keys->{DATATYPE};
	my @ret = ();

	return if ( not $type );

	if ( $type =~ /REQUEST/ ) {
		@ret = ( "DN", "CN", "EMAIL", "RA", "OPERATOR" );
	} elsif ( $type =~ /CERTIFICATE/ ) {
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

	my $dataType 	= $keys->{DATATYPE};	## VALID_CERTIFICATES ...
	my $inform	= $keys->{INFORM};	## PEM|DER|TXT|SPKAC|RENEW|RAW
	my $object	= $keys->{OBJECT};	## an OpenCA::xxxx object
	my $mode	= $keys->{MODE};	## ACTUALLY only UPDATE or NULL

	my %DB;
	my ( @exts, @attributes );
	my ( $converted, $baseType, $fileName, $headFileName, $attr );

	## Shall we give the ability to choose directly the
	## key ??? This is actually left out to provide a
	## very independent interface class... (huh?)
	my $serial     = $keys->{KEY};

	return if ( ($mode eq "UPDATE" ) and (not $serial));

	## if we have no db for that DATATYPE or no data then return
	return if ( (not $object) or (not exists $self->{dBs}->{$dataType}) );

	## Here we define the base type to decide where to store the
	## passed data
	return if ( not ($baseType = $self->getBaseType(DATATYPE=>$dataType)));

	## If the data is convertible, let's have only one internal
	## format to handle with
	if ( not $inform ) {
		$inform = "PEM"
	}

	## if ( $inform =~ /SPKAC|RENEW|RAW|REVOKE|TXT/ ) {
	## 	$converted = $object->getParsed()->{ITEM};
	## } else {
	## 	if( $inform ne $self->{defStoredFormat} ) {

	if( $object->getParsed()->{TYPE} =~ /SPKAC|RENEW|REVOKE/ ) {
		$converted = $object->getParsed()->{ITEM};
	} else {
			if( $self->{defStoredFormat} eq "PEM" ) {
				$converted = $object->getPEM();
			} elsif ( $self->{defStoredFormat} eq "DER" ) {
				$converted = $object->getDER();
			} else {
				$converted = $object->getParsed()->{ITEM};
			}
	}

	## Now we have BASIC and EXTENDED DATATYPE, we store the data
	## into the basic dB
	$fileName = "$self->{dbDir}/$self->{dBs}->{$baseType}->{FILE}";
	$headFileName = "$self->{dbDir}/$self->{dBs}->{$baseType}->{INFO}";

	my $digest= $self->{backend}->getDigest( DATA=>$converted );

	if(($dataType !~ /CA_CERTIFICATE/) and ($dataType =~ /CERTIFICATE/)){
		$digest = $object->getParsed()->{SERIAL};
	}
 
	## We add the record and update the IDX one calling the addRecord()
	if( $mode eq "UPDATE" ) {
		return if ( not $self->updateRecord( FILENAME=>$fileName,
				KEY=>$digest, DATA=>$converted ));
	} else {
		return if ( not $self->addRecord( FILENAME=>$fileName,
				KEY=>$digest, DATA=>$converted, MODE=>"RAW" ));
	}

	## Let's update the INFO value
	if( exists $object->getParsed()->{HEADER} ) {
		return if( not $self->saveHash( FILENAME=>$headFileName,
			KEY=>$digest, IDX=>$object->getParsed()->{HEADER} ));
	}

	## Now add the couple SERIAL=HASH to the appropriate DATATYPE dB
	## We get the serial (that identifies the object when searching or
	if( $baseType eq $dataType ) {
		$dataType = "VALID_" . $dataType;
	}

	$fileName = "$self->{dbDir}/$self->{dBs}->{$dataType}";
	return if ( not $serial = $self->addRecord( FILENAME => $fileName,
						KEY=>$serial, DATA=>$digest));

	## Let's add extra searching path... the attr list will be stored
	## into the search dB.
	## we expect a great number of requests archivied/processed by the
	## same RA or OPERATOR ( for example ), we'll see later...
	@attributes = $self->getSearchAttributes( DATATYPE=>$baseType );

	## Get the new filename to use from the search subsection
	$fileName = "$self->{dbDir}/$self->{dBs}->{SEARCH}->{$dataType}";

	for $attr ( @attributes ) {
		my ( $key, $list, $attrVal );

		## Here we distinguish between parameteres in the header
		if( $attr =~ /RA/ ) {
			$attrVal = $object->getParsed()->{HEADER}->{$attr};
		} else {
			$attrVal = $object->getParsed()->{$attr};
		}
	
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
	return $serial;
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

		$body = $tmpBody;
	}
	
	## This $txtItem have the original object as it was stored
	## with all infos in it
	$txtItem = $self->{beginHeader} . "\n" . $header . "\n" .
				$self->{endHeader} . "\n" . $body ;

	## If it was asked only the text version, we send out only that
	## without generating an OBJECT from it
	if( $mode eq "RAW" ) {
		return $txtItem;
	}

	## Build an Object from retrieved DATA
	if( $baseType eq "CERTIFICATE" ) {
		$item = new OpenCA::X509( SHELL=>$self->{backend},
			 	          INFORM=>$self->{defOutFormat},
			        	  DATA=>$txtItem );
	} elsif ( $baseType eq "CRL" ) {
		$item = new OpenCA::CRL( SHELL=>$self->{backend},
			        	 INFORM=>$self->{defOutFormat},
			        	 DATA=>$txtItem );
	} elsif ( $baseType eq "REQUEST" ) {
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

	$item->{parsedItem}->{DBKEY} = $serial;

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

	my ( $idx, $fileName, $item );

	$fileName = "$self->{dbDir}/$self->{dBs}->{$dataType}";

	return if (not $idx = $self->getIndex( DATATYPE=>$dataType,
						FILENAME=>$fileName ));

	while( $key < $idx->{NEXT} ) {
		$key++;
		last if( $item = $self->getItem( DATATYPE=>$dataType,
						MODE=>$mode, KEY=>$key ));
	}

	if( $key >= $idx->{NEXT} ) {
		return;
	} else {
		return $item;
	}
}

sub getPrevItem {
	## Get Prev Item given a serial number

	my $self = shift;
	my $keys = { @_ };

	my $key 	= $keys->{KEY};
	my $dataType 	= $keys->{DATATYPE};
	my $mode 	= $keys->{MODE};

	my ( $idx, $fileName, $item );

	$fileName = "$self->{dbDir}/$self->{dBs}->{$dataType}";
	return if (not $idx = $self->getIndex( DATATYPE=>$dataType,
						FILENAME=>$fileName ));

	$key = $idx->{NEXT} if ( not $key );
	while( $key > -1 ) {
		$key--;
		last if( $item = $self->getItem( DATATYPE=>$dataType,
						MODE=>$mode, KEY=>$key ));
	}
	if( $key == -1 ) {
		return;
	}

	if( $mode eq "RAW" ) {
		return $key;
	} else {
		return $item;
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

	## print "::: BEGIN DELETING => $key $type\n";
	return if ( (not $key ) or ( not exists $self->{dBs}->{$type}) );

	my $baseType = $self->getBaseType( DATATYPE=>$type );

	## print "::: GETTING ITEM => $key $fileName\n";
	if( not $item = $self->getItem( DATATYPE=>$type, KEY=>$key )) {
		return;
	}

	$fileName = "$self->{dbDir}/$self->{dBs}->{$type}";
	## print "::: GETTING HASH => $key $fileName\n";
	return if (not $hash = $self->getData( FILENAME=>$fileName, KEY=>$key));

	$fileName = "$self->{dbDir}/$self->{dBs}->{SEARCH}->{$type}";
	## print "::: SEARCHING => $fileName\n";
	## print "::: ITEM DATA HASH => $hash\n";
	for $i ( $self->getSearchAttributes( DATATYPE=>$type ) ) {
		$sKey = "$i:" . $item->getParsed()->{$i};

		## print "::: ITEM HASH => $sKey\n";
		next if ( not $sVal = $self->getData( FILENAME=>$fileName,
							KEY=>$sKey ));

		$sVal =~ s/\:$key//;
		if( not $sVal ) {
			$self->deleteRecord(FILENAME=>$fileName, KEY=>$sKey,
						DATATYPE=>$type, MODE=>"RAW" );
			## print "::::: ERASED RECORD $sKey!\n";
		} else {
			return if ( not $self->saveData( FILENAME=>$fileName,
						KEY=>$sKey, DATA=>$sVal ));
		}
		## print "::: FIELD DELETED OK.\n";
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
	## This function should be used in conjunction with searching function
	## use the elements sub instead if you wish to know how many specific
	## dB elements are there (such as VALID_CERTIFICATES, etc ... )

	my $self = shift;
	my $keys = { @_ };

	return $self->searchItem( MODE=>"ROWS", @_ );
}

sub searchItem {

	## Returns the requested item LIST. You can search for
	## generic DATATYPE such as CERTIFICATE|REQUEST|CRL
	## or restricted type (EXPIRED_CERTIFICATE|REVOKED_CERTIFICATE|
	## VALID_CERTIFICATE...

	my $self = shift;
	my $keys = { @_ };

	my @retList = ();
	my $dataType;

	my $type   = $keys->{DATATYPE};
	my $mode   = $keys->{MODE};

	## We remove the old value, we want to pass it by hand to the
	## searchDB function
	delete $keys->{DATATYPE};

	foreach $dataType ( keys %{$self->{dBs}} ) {
		next if ( ( $dataType =~ /HASH/ ) or 
			( $dataType =~
				/$self->getBaseType( DATATYPE=>$dataType )/ ));
		if ( $dataType =~ /$type/i ) {
			my @plist = $self->searchItemDB( DATATYPE=>$dataType,
									@_ );
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
	my $keys = { @_ };

	## Get the dataType
	my $dataType 	= $keys->{DATATYPE};
	my $mode	= $keys->{MODE};

	my ( $fileName, $txtList, $key, $dbVal, $dbKey, $ret, $i );

	my @retList = ();
	my @objRetList=();

	## We delete the not needed keys
	delete( $keys->{DATATYPE} );
	delete( $keys->{MODE} );

	## Let's Build the SEARCH dB fileName
	$fileName = "$self->{dbDir}/$self->{dBs}->{SEARCH}->{$dataType}";

	## For every keyword let's get the list of values
	while( ($dbKey, $dbVal) = each %$keys ) {
		$key = "$dbKey:$dbVal";

		$txtList->{$dbKey} = $self->getData( FILENAME=>$fileName,
								KEY=>$key );
	}

	## We want to eliminate any reference to serials who don't have
	## all the fields required, here we buld a list with number of
	## time a serial appear
	$i = 0;
	foreach $key ( keys %$txtList ) {
		my ( @tmp, $tmpSer );

		$i++; 	## Here we have the number of fields checked, a serial
			## should be present each time into the final record;

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
		}
	}

	return @retList if( $mode eq "ROWS" );
	
	for $i (@retList) {
		my $obj;

		next if ( not $obj = $self->getItem( DATATYPE=>$dataType,
							KEY=>$i ));
		push( @objRetList, $obj );
	}

	return @objRetList;
}

sub listItems {
	my $self = shift;
	my $keys = { @_ };

	my $dataType	= $keys->{DATATYPE};
	my $items 	= $keys->{ITEMS};
	my $from 	= $keys->{FROM};
	my $to 		= $keys->{TO};
	my $mode	= $keys->{MODE};

	my ( @ret, $retItems, $i, $tmpObj, $dbKey );

	return if( not $dataType );

	$dbKey = ( $self->getPrevItem( DATATYPE=>$dataType, KEY=>$from,
							 MODE=>"RAW") or "0" );
	if( not $to ) {
		$retItems = $dbKey + $items;
	} else {
		$retItems = $to;
	}

	for ( $i = 0; $i < $retItems; $i++ ) {

		last if ( not $tmpObj = $self->getNextItem( DATATYPE=>$dataType,
					MODE=>$mode, KEY=>$dbKey ));
		if( $mode ne "RAW" ) {
			$dbKey = $tmpObj->getParsed()->{DBKEY};
		} else {
			$dbKey = $tmpObj;
		}
		push( @ret, $tmpObj );
	}

	return @ret;
}

##sub searchDB {
##	my $self = shift;
##	my $keys = { @_ };
##
##	my $type     = $keys->{DATATYPE};
##	my $mode     = $keys->{MODE};
##	## my $from     = $keys->{FROM};
##	## my $to       = $keys->{TO};
##	## my $maxItems = $keys->{MAX_ITEMS};
##
##	my $tmp, $ret = 0, $counter = 0;
##	my $matched, $i;
##	my @retList = ();
##	my $dbDir = $self->{dbDir};
##	my $dbValue, $dbKey, $itNum, $ret;
##	my %DB;
##
##	$fileName = "$dbDir/$fileName";
##
##	## Match HASH used to match item
##	my $match = $keys;
##	delete( $match->{DATATYPE} );
##	delete( $match->{MODE} );
##	delete( $match->{FROM} );
##	delete( $match->{TO} );
##	delete( $match->{MAX_ITEMS} );
##
##	$itNum = $self->elements( DATATYPE=>$type );
##
##	dbmopen( %DB, "$fileName", 0600 ) or return;
##
##	if( ( $type =~ /CERTIFICATE|REQUEST|CRL/g )
##				and ( $type !~ /VALID_CA_CERTIFICATE/)
##				and ( $type !~ /EXPIRED_CA_CERTIFICATE/) ) {
##
##		$from = 0 if ( not $from );
##		$to = $self->elements( DATATYPE=>$type ) if (not $to);
##
##		if( ( $maxItems) and ( $to > ($from + $maxItems )) ) {
##			$to = $from + $maxItems;
##		}
##
##		## $counter = $from;
##
##		$counter = 0;
##		my $i = -1;
##		my $returned = 0;
##		my $lastElement = ( hex ( $DB{LAST} ) or 10000 );
##
##		while(  ( $returned <= $to ) and ( $counter < $itNum ) and
##			( $i <= $lastElement ) and ( $counter <= $to ) ) {
##
##			$i++;
##
##			$dbKey = $self->toHex( $i );
##
##			if ( not $dbValue = $DB{$dbKey}  ) {
##				next;
##			} else {
##				$counter++;
##				next if( $counter < $from );
##			}

##			next if ( not $elem = $self->getElement(
##					DATATYPE=>$type,
##					INFORM=>$self->{defStoredFormat},
##				    	DATA=>$dbValue ));
##
##			## Let's check if it is a VALID_CERTIFICATE and
##			## should be EXPIRED ...
##			if( $type =~ /VALID_CERTIFICATE/ ) {
##				my $now = $self->{tools}->getDate();
##				my $notAfter = $elem->getParsed()->{NOT_AFTER};
##
##				if( $self->{tools}->cmpDate( DATE_1=>$notAfter,
##						    DATE_2=>$now ) <= 0 ) {
##
##						$self->{tools}->cmpDate( 
##							DATE_1=>$notAfter,
##							DATE_2=>$now )  .
##								 "<BR>\n";
##
##					$self->storeItem( 
##						DATATYPE=>'EXPIRED_CERTIFICATE',
##						DATA=>$elem->getPEM() );
##
##					$self->deleteItem( DATATYPE=>$type,
##						KEY=>$dbKey,
##						DBLOCK=>%DB );
##
##					next;
##				}
##
##			}
##
##			$matched = $self->matches( $elem, $type, $match );
##
##			if( $matched ) {
##				my $item = { KEY=>$dbKey, 
##					     VALUE=>$elem,
##					     DATATYPE=>$type };
##
##				if( "$mode" eq "ROWS" ) {
##					$ret++;
##				} else {
##					push @retList, $item;
##				}
##				$returned++;
##			}
##		}
##
##	##} elsif ( $type =~ /CRL/ ) {
##	##	foreach $dbValues ( sort byLastUpdate values %DB ) {
##	##		
##	##		print "::: KEY => $dbValue<BR>\n";
##
##	##		next if ( not $elem = $self->getElement(
##	##						DATATYPE=>$type,
##	##			    			DATA=>$dbValue ));
##
##	##		$matched = $self->matches( $elem, $type, $match );
##
##	##		if( $matched ) {
##	##			my $item = { KEY=>$dbKey, 
##	##				     VALUE=>$elem,
##	##				     DATATYPE=>$type };
##
##	##			if( "$mode" eq "ROWS" ) {
##	##				$ret++;
##	##			} else {
##	##				push @retList, $item;
##	##			}
##	##		}
##	##	}
##	} else {
##		$maxItems-- if( $maxItems );
##
##	    	while ( ($dbKey, $dbValue) = each  %DB ) {
##			my $elem, $parsedItem, $i;
##
##			if( $reserved =~ /$dbKey/i ) {
##				next;
##			}
##
##			$counter++;
##
##			next  if( ($from) and ($counter < $from) );
##			break if( ($to) and ($counter > $to) );
##			last if ( ($maxItems) and ($#retList >= $maxItems) );
##
##			next if ( not $elem = $self->getElement(
##					DATATYPE=>$type,
##					INFORM=>$self->{defStoredFormat},
##				    	DATA=>$dbValue ));
##
##			$matched = $self->matches( $elem, $type, $match );
##
##			## Let's check if it is a CA_CERTIFICATE and
##			## should be EXPIRED ...
##			if( $type =~ /^CA_CERTIFICATE/ ) {
##				my $now = $self->{tools}->getDate();
##
##				my $notAfter = $elem->getParsed()->{NOT_AFTER};
##
##				if( $self->{tools}->cmpDate( DATE_1=>$notAfter,
##						    DATE_2=>$now ) <= 0 ) {
##
##						$self->{tools}->cmpDate( 
##							DATE_1=>$notAfter,
##							DATE_2=>$now )  .
##								 "<BR>\n";
##
##					$self->storeItem( 
##					     DATATYPE=>'EXPIRED_CA_CERTIFICATE',
##					     DATA=>$elem->getPEM() );
##
##					$self->deleteItem( DATATYPE=>$type,
##						KEY=>$dbKey,
##						DBLOCK=>%DB );
##
##					next;
##				}
##
##			}
##
##			if( $matched ) {
##				my $item = { KEY=>$dbKey, 
##					     VALUE=>$elem,
##					     DATATYPE=>$type };
##
##				if( "$mode" eq "ROWS" ) {
##					$ret++;
##				} else {
##					push @retList, $item;
##				}
##			}
##	    	}
##	}
##	dbmclose( %DB );
##
##	if( "$mode" eq "ROWS" ) {
##		return $ret;
##	} else {
##		return @retList;
##	}
##};

##sub getElement {
##
##	my $self = shift;
##
##	my $keys   = { @_ };
##	my $type   = $keys->{DATATYPE};
##	my $data   = $keys->{DATA};
##	my $inform = $keys->{INFORM};
##	my $obj;
##
##	if( $type =~ /CERTIFICATE/i ) {
##		$obj = new OpenCA::X509( SHELL=>$self->{backend},
##			        INFORM=>$inform,
##			        DATA=>$data );
##	} elsif ( $type =~ /CRL/i ) {
##		$obj = new OpenCA::CRL( SHELL=>$self->{backend},
##			        INFORM=>$inform,
##			        DATA=>$data    );
##	} elsif ( $type =~ /CRR/i ) {
##		$obj = new OpenCA::CRR( SHELL=>$self->{backend},
##			        INFORM=>$inform,
##			        DATA=>$data    );
##	} elsif ( $type =~ /REQUEST/i ) {
##		$format = $inform;
##
##		$format = "SPKAC" if( $data    =~ /SPKAC =/ );
##		$format = "RENEW" if( $data    =~ /RENEW =/ );
##
##		$obj = new OpenCA::REQ( SHELL=>$self->{backend},
##			        INFORM=>$format,
##			        DATA=>$data    );
##	}
##
##	return $obj;
##}


##sub matches {
##
##	my $self = shift;
##	my $item = shift;
##	my $type = shift;
##	my $match = shift;
##
##	my $parsedItem;
##	my $ret = 1;
##
##	return if (not $item);
##
##	$parsedItem = $item->getParsed();
##
##	return if ( not $parsedItem );
##
##	foreach $key (keys %$match) {
##		my $tmpMatch;
##
##		if( $key ne "DATE" ) {
##			next if( (not exists($parsedItem->{$key}))
##		      		or (not exists($match->{$key})) );
##		}
##
##		$tmpMatch = $match->{$key};
##
##		if( $key =~ /NOT_BEFORE|LAST_UPDATE/ ){
##			if( $self->{tools}->cmpDate(
##					DATE_1=>$parsedItem->{$key},
##					DATE_2=>$tmpMatch ) > 0 ) {	
##				$ret = 0;
##				last;
##			}
##
##		} elsif( $key =~ /NOT_AFTER|NEXT_UPDATE/ ){
##
##			if( $self->{tools}->cmpDate(
##					DATE_1=>$parsedItem->{$key},
##					DATE_2=>$tmpMatch ) < 0 ) {	
##
##				$ret = 0;
##				last;
##			}
##
##		} elsif( $key =~ /DATE/ ){
##
##			my $startDate, $endDate;
##
##			if( $type =~ /CRL/ ) {
##				$startDate = $parsedItem->{LAST_UPDATE};
##				$endDate = $parsedItem->{NEXT_UPDATE};
##			} else {
##				$startDate = $parsedItem->{NOT_BEFORE};
##				$endDate = $parsedItem->{NOT_AFTER};
##			}
##
##			if( not $self->{tools}->isInsidePeriod(
##				DATE=>$tmpMatch, START=>$startDate,
##						END=>$endDate)) {
##
##				$ret = 0;
##				last;
##			}
##
##		} elsif( $parsedItem->{$key} !~ /$tmpMatch/i ) {
##
##			$ret = 0;
##			last;
##		}
##	}
##
##	return $ret;
##
##}

sub byKey { $a->{KEY} <=> $b->{KEY} };

sub getTimeString {

	my $self = shift;
	my  ( $ret, @T );

	@T = gmtime( time() );
	$ret = sprintf( "%4.4d%2.2d%2.2d%2.2d%2.2d%2.2d%6.6d",
			 $T[5]+1900, $T[4], $T[3], $T[2], $T[1], $T[0], ${$} );

	return $ret;

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
		retriexe the IDX from a DBM file;

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
		initialize the dB structure;

	createDB (*) {};
		create and initialize the dBs;

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
		
	deleteItem {};

	elements {};
		returns number of elements of a given DATATYPE;

	rows {};
		return number of elements matching a serach;

	searchItem {};
		returns objects/serials matching the search on generic
		datatypes (i.e. CERTIFICATE, REQUEST);

	searchItemDB (*) {};
		returns objects/serials matching the search on exact
		datatypes (i.e. VALID_CERTIFICATE, PENDING_REQUEST);
		
	searchDB {};
		to be removed;

	getElement {};
		to be removed;

	matches {};
		to be removed;

	byKey { $a->{KEY} <=> $b->{KEY} };
		to be removed;

	getTimeString {};
		not currently used;

	toHex (*) {};
		convert a decimal to an hex;

=head1 AUTHOR

Massimiliano Pala <madwolf@openca.org>

=head1 SEE ALSO

OpenCA::OpenSSL, OpenCA::X509, OpenCA::CRL, OpenCA::REQ,
OpenCA::TRIStateCGI, OpenCA::Configuration, OpenCA::Tools

=cut
