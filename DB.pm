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

## the module's errorcode is 21
##
## function
##
## new			11
## initDB		21
## getSubTypes		31
## dbOpen		41
## dbClose		42
## storeItem		51
## parseDataType	32
## getSearchAttributes	33
## getItem		61
## getNextItem		62
## getPrevItem		63
## deleteItem		52
## updateStatus		53
## elements		64
## rows			65
## searchItems		66
## listItems		67
## createObject		43
## getSignature		71
## getBody		72
## getHeader		73
## compareNumeric	81
## compareHexSerial	82
## compareString	84
## toHex		83

use strict;

package OpenCA::DB;

our ($errno, $errval);

## We must store/retrieve CRLs,CERTs,REQs objects:
## proper instances of object management classes are
## needed.

use OpenCA::REQ;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::OpenSSL;
use OpenCA::Tools;

## Mandatory use of BerkeleyDB
use DB_File;

$OpenCA::DB::VERSION = '2.0.5';

my %params = (
  dbDir           => undef,
  backend         => undef,
  dBs             => undef,
  defStoredFormat => undef,
  defInFormat     => undef,
  defOutFormat    => undef,
  tools           => undef,
  dbms            => undef,
  dbms_h          => undef,
  dbms_search     => undef,
  dbms_search_h   => undef,
  errno           => undef,
  errval          => undef
);

sub setError {
	my $self = shift;

	if (scalar (@_) == 4) {
		my $keys = { @_ };
		$errval = $keys->{ERRVAL};
		$errno  = $keys->{ERRNO};
	} else {
		$errno  = $_[0];
		$errval = $_[1];
	}

	## save the last DB-error
	$OpenCA::DB::errno  = $errno;
	$OpenCA::DB::errval = $errval;

	## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
	return undef;
}

sub errno {
	return $OpenCA::DB::errno;
}

sub errval {
	return $OpenCA::DB::errval;
}

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

        return $self->setError (2111011, "OpenCA::DB->new: No crypto-backend present.")
		if (not $self->{backend});
        return $self->setError (2111012, "OpenCA::DB->new: No databasedirectory present.")
        	if (not $self->{dbDir});

	$self->{dBs}->{CERTIFICATE}		= "certificates";
	$self->{dBs}->{SEARCH}->{CERTIFICATE}	= "search_certs";

	$self->{dBs}->{CA_CERTIFICATE}		= "cacertificates";
	$self->{dBs}->{SEARCH}->{CA_CERTIFICATE}= "search_cacerts";

	$self->{dBs}->{REQUEST}			= "requests";
	$self->{dBs}->{SEARCH}->{REQUEST}  	= "search_requests";

	$self->{dBs}->{CRR}			= "crrs";
	$self->{dBs}->{SEARCH}->{CRR}  		= "search_crrs";

	$self->{dBs}->{CRL}			= "crls";
	$self->{dBs}->{SEARCH}->{CRL}		= "search_crls";

	## Defaults storage format. This does not apply to SPKAC requests
	$self->{defStoredFormat} 		= "PEM";
	$self->{defOutFormat}    		= "PEM";
	$self->{defInFormat}    		= "PEM";
 	$self->{beginHeader} 			= "-----BEGIN HEADER-----";
 	$self->{endHeader} 			= "-----END HEADER-----";

	return $self->setError (2111021, "OpenCA::DB->new: Cannot initialize OpenCA::Tools.")
		if ( not $self->{tools} = new OpenCA::Tools());

	if( not ( opendir( DIR, $self->{dbDir} ))) {
		return $self->setError (2111031, "OpenCA::DB->new: Cannot open databasedirectory.");
	} else {
		closedir(DIR);
	};

	return $self->setError (2111041, "OpenCA::DB->new: Cannot initialize database ($errno)\n$errval")
		if (not $self->initDB(MODE=>$keys->{MODE}));

	return $self;
}

sub initDB {
	## Generate a new db File and initialize it allowing the
	## DB to keep track of the DB status

	my $self = shift;
	my $keys = { @_ };

	## Mode, now ignored, actually
	my $mode      = $keys->{MODE};
	my @dataTypes = ( "CA_CERTIFICATE", "CERTIFICATE", "CRR",
			  "REQUEST", "CRL" );

	## Class parameters
	my $dbDir     = $self->{dbDir};

	## Private parameters
	my ( $type, $baseType, $filename, $flags, @subTypes );

	foreach $type (@dataTypes) {
		@subTypes = $self->getSubTypes( $type );

		## For each subtype (PENDING, etc...) we go to the
		foreach (@subTypes) {
			my $ret;

			if( not $self->dbOpen( DATATYPE => "$_\_$type", 
				FILENAME=>$filename, MODE=>$mode )) {
				return $self->setError (2121021,
							"OpenCA::DB->initDB: Cannot open database ".
							"with datatype ".$_."_".$type.", ".
							"filename $filename and ".
							"accessmode $mode ($errno)\n$errval.");
			};
			$self->dbClose( $self->{dbms} );
		}
	}

	return 1;
}

sub getSubTypes {
	my $self = shift;
	my $type = shift;

	my ( @subTypes );

	if( $type =~ /CERTIFICATE/ ) {
		@subTypes = ("VALID","REVOKED","SUSPENDED","EXPIRED" );
	} elsif ( $type =~ /REQUEST|CRR/ ) {
		@subTypes =("ARCHIVED","NEW","RENEW","PENDING","SIGNED","APPROVED","DELETED");
	} elsif ( $type =~ /CRL/ ) {
		@subTypes = ("VALID","EXPIRED","DELETED");
	}

	return ( @subTypes );
}

sub dbOpen {
	## Open the DB, the one requested using the DATATYPE, STATUS
	## couple:
	##	DATATYPE :: CERTIFICATE, REQUEST, CRR, CRL
	##	STATUS   :: PENDING, APPROVED, DELETED, VALID,
	##		    REVOKED, EXPIRED, SUSPENDED
	##	            NEW, RENEW, SIGNED
	my $self = shift;
	my $keys = { @_ };

	my $dataType = $keys->{DATATYPE};
	my $mode     = $keys->{MODE};

	my ( $db, $dbSearch, $filename, $baseType, $status, $flags );
	my ( %h, %h1, $binfo, $b2_info );

	( $baseType, $status ) = $self->parseDataType( $dataType );

	$status = $keys->{STATUS} if( not $status);

	$filename = $self->{dbDir} . "\/" .  lc( $status ) . "\_" .
				$self->{dBs}->{$baseType};

	return $self->setError (2141011, "OpenCA::DB->dbOpen: No filename specified.")
		if (not $filename);
	return $self->setError (2141012, "OpenCA::DB->dbOpen: No datatype specified.")
		if (not $dataType);
	return $self->setError (2141013, "OpenCA::DB->dbOpen: No status specified.")
		if (not $status);

	## Delete the file if "FORCE" mode is used and re-create it
	unlink( "$filename" ) if( defined $mode and $mode eq "FORCE" );

	$b2_info = new DB_File::BTREEINFO;
	if( $baseType =~ /^(CA_CERTIFICATE|CRL)/ ) {
		$b2_info->{'compare'} = \&compareString;
	} else {
		$b2_info->{'compare'} = \&compareNumeric;
	}

	$self->{dbms} = tie %h, "DB_File", "$filename", O_RDWR|O_CREAT, 
						0600, $b2_info
		or return $self->setError (2141021, "OpenCA::DB->dbOpen: Cannot initialize DBMS.");

	$filename = $self->{dbDir} . "\/" . lc( $status ) . "\_" .
	 			 $self->{dBs}->{SEARCH}->{$baseType};

	## Delete the file if "FORCE" mode is used and re-create it
	unlink( "$filename" ) if( defined $mode and $mode eq "FORCE" );

	$binfo = new DB_File::BTREEINFO;
	$binfo->{'flags'} = R_DUP;
	$self->{dbms_search} = tie %h1, "DB_File", "$filename",
					O_RDWR|O_CREAT, 0600, $binfo
		or return $self->setError (2141023, "OpenCA::DB->dbOpen: Cannot initialize searchengine.");

	$self->{dbms_h}		= \%h;
	$self->{dbms_search_h} 	= \%h1;

	return 1;
}

sub dbClose {
	## Closes an open DB file

	my $self = shift;
	my $db = shift;
	
	undef $self->{dbms} if( defined $self->{dbms} );
	untie $self->{dbms_h};

	undef $self->{dbms_search} if( defined $self->{dbms_search} );
	untie $self->{dbms_search_h};

	return 1;
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
	my $inform	= ( $keys->{INFORM} or $self->{defInFormat} );

	my $object	= $keys->{OBJECT};	## an OpenCA::xxxx object
	my $mode	= $keys->{MODE};	## ACTUALLY only UPDATE|NULL

	my ( $cursor, $item, $converted, $key, $value, $tmp);

	return $self->setError (2151011, "OpenCA::DB->storeItem: No datatype specified.")
		if (not $dataType);
	return $self->setError (2151012, "OpenCA::DB->storeItem: No object specified.")
		if (not $object);

	my $parsed	= $object->getParsed();
	my ( $baseType, $status ) = $self->parseDataType( $dataType );

	$item = $object->getItem ();
	$key  = $object->getSerial ($baseType); # CAs use digest and not cert's serial

	## determine old status
	my @status_list = ("NEW", "RENEW", "PENDING", "SIGNED", "APPROVED", "ARCHIVED", "DELETED",
                           "VALID", "EXPIRED", "SUSPENDED", "REVOKED");
        my $old_status = "";
	foreach my $scan_status (@status_list)
	{
		## is already present in DB?
		my $old_item = $self->getItem ( DATATYPE => $scan_status."_".$baseType, KEY => $key );
		if ($old_item)
		{
			$old_status = $scan_status;
			last;
		}
	}

	## Open the DB
	return $self->setError (2151021, "OpenCA::DB->storeItem: Cannot open database ($errno)\n$errval")
		if( not $self->dbOpen( DATATYPE=>$dataType ));

	if( not exists $self->{dbms_h}{$key} ) {
		## Update the DB Elements count
		if ( exists $self->{dbms_search_h}{"ELEMENTS"} ) {
		 	$tmp = $self->{dbms_search_h}{"ELEMENTS"};
			$tmp++;

			## Delete the record or we will duplicate it
			delete $self->{dbms_search_h}{"ELEMENTS"};

			## Store the new value
		 	$self->{dbms_search_h}{"ELEMENTS"}=$tmp;
			
		} else {
		 	$self->{dbms_search_h}{"ELEMENTS"}=1;
		}
	}
	$self->{dbms_h}{$key}=$item;

	## Updating the searching facility
	foreach ( $self->getSearchAttributes( $dataType )) {
		my ( $k, $v, $md5 );

		next if (not $value = ($parsed->{$_} or $parsed->{HEADER}->{$_}));

		$k = $value;
		$v = $key;

		if( $self->{dbms_search}->find_dup( $k, $v ) != 0 ) {
			$self->{dbms_search_h}{$k} = $key;
		};
	}

	$self->{dbms}->sync();
	$self->{dbms_search}->sync();
	$self->dbClose();

	## remove old status if it differs from new status
	if ($old_status and $old_status ne $status)
	{
		return $self->setError (2151081, "OpenCA::DB->storeItem: Cannot delete old status from the database ".
					"($errno)\n$errval")
			if (not $self->deleteItem( DATATYPE=>$old_status."_".$baseType,
                                                   KEY=>$key));
	}

	return 1;
}

sub parseDataType {
	my $self = shift;
	my $dataType = shift;

	my ( $k1, $k2 );

	if ($dataType =~ /CA_CERTIFICATE/) {
		$k2 = "CA_CERTIFICATE";
		$k1 = $dataType;
		$k1 =~ s/CA_CERTIFICATE//;
		$k1 =~ s/_$//;
	} else {
		( $k1, $k2 ) = ( $dataType =~ 
			/^([^\_]+)*\_*(CA_CERTIFICATE|CERTIFICATE|CRL|REQUEST|CRR)/);
	}

	## if( $k1 eq "" ) {
	## 	$k1 = "VALID" if ( $k2 =~ /CERTIFICATE|CRL/ );
	## 	$k1 = "PENDING" if ( $k2 =~ /REQUEST|CRR/ );
	## }

	return ( $k2, $k1 );
}

sub getSearchAttributes {
	my $self 	= shift;
	my $dataType    = shift;

	my @ret = ();
	my ( $baseType, $status );

	return $self->setError (2133011, "OpenCA::DB->getSearchAttributes: No datatype specified.")
		if ( not $dataType );

	( $baseType, $status ) = $self->parseDataType( $dataType );

	if ( $baseType =~ /REQUEST/ ) {
		if( $status =~ /NEW|RENEW|PENDING/ ) {
			@ret = ( "DN", "CN", "EMAIL", "RA", "SCEP_TID" );
		} elsif ( $status =~ /SIGNED|APPROVED/ ) {
			@ret = ( "RA", "DN", "CN", "EMAIL", "SCEP_TID", "OPERATOR" );
		} else {
			@ret = ( "DN","CN","EMAIL", "SCEP_TID" );
		}
        } elsif ( $baseType =~ /CRR/ ) {
		if( $status =~ /NEW|RENEW|PENDING|SIGNED|APPROVE|DELETED|ARCHIVED/ ) {
			@ret = ( "REVOKE_CERTIFICATE_SERIAL", "REVOKE_CERTIFICATE_DN",
				 "REVOKE_CERTIFICATE_KEY_DIGEST" );
		} else {
			@ret = ( "REVOKE_CERTIFICATE_SERIAL", "REVOKE_CERTIFICATE_DN" );
		}
	} elsif ( $baseType =~ /CA_CERTIFICATE/ ) {
		@ret = ( "DN", "CN", "EMAIL", "KEY_DIGEST", "PUBKEY" );
	} elsif ( $baseType =~ /CERTIFICATE/ ) {
		@ret = ( "DN", "CN", "EMAIL", "KEY_DIGEST", "PUBKEY", "CSR_SERIAL" );
	};

	return @ret;
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

	my ( $baseType, $status, $cursor, $obj, $val );

	my $dataType   	= $keys->{DATATYPE};

	my $key    	= $keys->{KEY};    ## Key passed when stored item
	my $mode   	= $keys->{MODE};   ## Actually only RAW or NULL

	return $self->setError (2161011, "OpenCA::DB->getItem: No datatype specified.")
		if ( not $dataType );

	( $baseType, $status ) = $self->parseDataType( $dataType );

	if ($baseType =~ /$dataType/i) {
		my @statuslist;

		## the order is important to fix buggy code!!!
		if ($baseType =~ /CA_CERTIFICATE/) {
			@statuslist = ("EXPIRED", "VALID");
		} elsif ($baseType =~ /CERTIFICATE/) {
			@statuslist = ("REVOKED", "SUSPENDED", "EXPIRED", "VALID");
		} elsif ($baseType =~ /CRL/) {
			@statuslist = ("VALID");
		} elsif ($baseType =~ /REQUEST/) {
			@statuslist = ("ARCHIVED", "DELETED", "APPROVED", "SIGNED", "PENDING", "RENEW", "NEW");
		} elsif ($baseType =~ /CRR/) {
			@statuslist = ("ARCHIVED", "DELETED", "APPROVED", "SIGNED", "PENDING", "NEW");
		} else {
			## unknown basetype
			return $self->setError (2161012, "OpenCA:DB->getItem: Unknown basetype.");
		}

		## try to find an object
		foreach $status (@statuslist) {
			my $item = $self->getItem (
						DATATYPE => $status."_".$baseType,
						KEY => $key,
						MODE => $mode);
			return $item if ($item);
		}

		## object not found
		return $self->setError (2161013, "OpenCA:DB->getItem: Object not found in database ($errno)\n$errval.");
	}

	return $self->setError (2161021, "OpenCA::DB->getItem: Cannot open database ($errno)\n$errval")
		if ( not $self->dbOpen( DATATYPE=>$dataType, STATUS=>$status));

	## Retrieve the object
	return $self->setError (2161022, "OpenCA::DB->getItem: The content of the databasefield is empty.")
		if ( $self->{dbms}->get ($key, $val) != 0 );

	## If MODE eq "RAW" we simply send the object out.
	if( $mode eq "RAW" ) {
		$self->dbClose();
		return $val;
	}
	## If mode ne "RAW" we build the OBJECTS and return their list.
	$obj = $self->createObject( DATATYPE=>$dataType, DATA => $val);
	$obj->getParsed()->{DBKEY} = $key;

	## We return the object(s)
	$self->dbClose();
	return $obj;

}

sub getNextItem {
	## Get Next Item given a serial number

	my $self = shift;
	my $keys = { @_ };

	my $key 	= $keys->{KEY};
	$key = -1 if (not defined $key);
	my $dataType 	= $keys->{DATATYPE};
	my $mode 	= $keys->{MODE};

	return $self->setError (2162021, "OpenCA::DB->getNextItem: Cannot open database ($errno)\n$errval")
		if (not $self->dbOpen( DATATYPE=>$dataType));

	my $dbstat;
	my $val;
	if ( ($self->{dbms}->seq($key, $val, R_CURSOR) != 0) or
	     ($keys->{KEY} != $key) ) {
		## the key doesn't exist
		$dbstat = $self->{dbms}->seq($key, $val, R_FIRST);
	} else {
		do {
			$dbstat = $self->{dbms}->seq($key, $val, R_NEXT );
		} while (($dbstat == 0) and ($key eq "ELEMENTS"));
	}

	return undef
		if ($dbstat < 0);

	## Return object (if any)
	return $self->getItem( DATATYPE=>$dataType, MODE=>$mode, KEY=>$key);
}

sub getPrevItem {
	## Get Prev Item given a serial number

	my $self = shift;
	my $keys = { @_ };

	my $key 	= $keys->{KEY};
	$key = -1 if (not exists $keys->{KEY});
	my $dataType 	= $keys->{DATATYPE};
	my $mode 	= $keys->{MODE};

	return $self->setError (2163021, "OpenCA::DB->getPrevItem: Cannot open database ($errno)\n$errval")
		if (not $self->dbOpen( DATATYPE=>$dataType));

	my $dbstat;
	my $val;
	if ( ($key == -1) or
	     ($self->{dbms}->seq($key, $val, R_CURSOR) != 0) or
	     ($keys->{KEY} != $key) ) {
		## the key doesn't exist
		$dbstat = $self->{dbms}->seq($key, $val, R_LAST);
	} else {
		do {
			$dbstat = $self->{dbms}->seq($key, $val, R_PREV );
		} while (($dbstat == 0) and ($key eq "ELEMENTS"));
	}

	return undef
		if ($dbstat < 0);

	## Return object (if any)
	return $self->getItem( DATATYPE=>$dataType, MODE=>$mode, KEY=>$key);
}

sub deleteItem {

	## Delete an Item Entry from the DB

	my $self = shift;
	my $keys = { @_ };

	my $dataType    = $keys->{DATATYPE};
	my $key         = $keys->{KEY};

	return $self->setError (2152011, "OpenCA::DB->deleteItem: No datatype specified.")
		if (not $dataType);
	return $self->setError (2152012, "OpenCA::DB->deleteItem: No key specified.")
		if (not $dataType);

	my ( $val, $cursor, $c_stat, @attrs, $obj, $parsed );
	my ( %h, %sh );

	my ( $baseType, $status ) = $self->parseDataType( $dataType );

	## Base Status is VALID
	$status = "VALID" if ( not $status );

	return $self->setError (2152021, "OpenCA::DB->deleteItem: Cannot load object from database ($errno)\n$errval")
		if (not $obj = $self->getItem(DATATYPE=>$dataType,KEY=>$key));
	return $self->setError (2152022, "OpenCA::DB->deleteItem: Cannot open database ($errno)\n$errval")
		if ( not $self->dbOpen( DATATYPE=>$dataType, STATUS=>$status));
	return $self->setError (2152023, "OpenCA::DB->deleteItem: Key doesn't exist in the database ($errno)\n$errval")
		if( not exists $self->{dbms_h}{$key} );

	delete $self->{dbms_h}{$key};

	## Get Parsed Object
	$parsed = $obj->getParsed();

	## Delete The Search Objects
	foreach ( $self->getSearchAttributes( $dataType )) {
		my ( $k, $v, $md5 );

		next if( not $val = $parsed->{$_} );

		## if( $_ eq "KEY" ) {
		## 	## We do add an hash instead of the real Key
		## 	$md5 = new Digest::MD5;
		## 	$md5->add( $val );
		## 	$k = $md5->hexdigest();
		## } else {
		## 	$k = $val;
		## }

		$k = $val;

		if ( $self->{dbms_search}->find_dup( $k, $key ) == 0 ) {
			$self->{dbms_search}->del_dup( $k, $key );
		}
	}

	## Update the DB Elements count
	if( not exists $self->{dbms_search_h}{"ELEMENTS"} or 
				$self->{dbms_search_h}{"ELEMENTS"} <= 1 ) {
		$self->{dbms_search_h}{"ELEMENTS"}= 0;
	} else {
		$self->{dbms_search_h}{"ELEMENTS"}--;
	}
	
	$self->dbClose();
	return 1;
}

## this function is now deprecated
sub updateStatus {

	## Updates the status of an element, in DBMS actually
	## moving data to the new "status" DB (i.e. EXPIRED,
	## REVOKED, etc... )

	my $self = shift;
	my $keys = { @_ };

	return $self->storeItem (DATATYPE => $keys->{NEWTYPE}, OBJECT => $keys->{OBJECT});
}

sub elements {

	## Returns number of elements contained in a dB. This number
	## is stored in the ELEMENTS key and it is updated each time
	## the dB module operates on the db.

	my $self = shift;
	my $keys = { @_ };

	my $dataType = $keys->{DATATYPE};
	my ( $ret );

	if (not $self->dbOpen(DATATYPE=> $dataType)) {
		## perhaps a datatype without a status
		my ($baseType, $status) = $self->parseDataType ($dataType);
		if ($status) {
			return $self->setError (2164011, "OpenCA::DB->elements: Cannot open database ($errno)\n$errval")
		}
		my @list = $self->searchItems (DATATYPE => $dataType, MODE => "RAW");
		return scalar @list;
	}

	$ret = ( $self->{dbms_search_h}{"ELEMENTS"} or "0" );

	$self->dbClose();

	return $ret;
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
	my ( $count, $key, $obj, @dupList, %ret );
	my ( $dbstat, $val, @subList, $st );

	my $dataType   = $keys->{DATATYPE};
	my $mode       = $keys->{MODE};

        my ( $baseType, $status ) = $self->parseDataType($dataType);

	## If no "status" is supplied we search the whole DB
	if( not $status ) {
		@subList = $self->getSubTypes( $baseType );
	} else {
		@subList = ( $status );
	}

	## Let's search
	foreach $st ( @subList ) {

		## Build the full dataType
		$dataType = "${st}_${baseType}";

                ## If Attribute Serial is an exact Search
                if( exists( $keys->{SERIAL}) ) {
                        $obj = $self->getItem( DATATYPE=>$dataType,
                                        KEY=>$keys->{SERIAL} );
                        push( @retList, $obj ) if( $obj );
                        next;
                }

		## Open DBMS
		return $self->setError (2166011, "OpenCA::DB->searchItems: Cannot open database ($errno)\n$errval")
			if( not $self->dbOpen( DATATYPE=>$dataType ));

		$count = 0;

		## If $count is 0 at the end, then it is a searchList
		foreach( $self->getSearchAttributes( $dataType )) {
			$count++ if( exists $keys->{$_} );
		}

		if( $count == 0 ) {
			push (@retList, $self->listItems(DATATYPE=>$dataType));
		} else {
			$count = 0;
			## Check every attribute
			foreach ( $self->getSearchAttributes( $dataType )) {
				next if( $keys->{$_} eq "" );

				$key = $keys->{$_};

				## Get results for this search attribute
				@dupList = $self->{dbms_search}->get_dup($key);

				foreach (@dupList) {
					next if ((exists $ret{$_}) or 
					     (not exists $self->{dbms_h}{$_}));

					## We don't want to duplicate the work
					$ret{$_}=1;
	
					if( $mode =~ /ROWS/i ) {
						$count++;
						next;
					} elsif ( $mode eq "RAW" ) {
						push(@retList, $self->{dbms_h}{$_} );
					} else {
						$obj = $self->createObject(
						    DATATYPE   => $dataType,
						    DATA       => $self->{dbms_h}{$_});
						$obj->getParsed()->{DBKEY} = $_;
						$obj->{DATATYPE}= $dataType;
						push(@retList,$obj) if ($obj);
					}
				}
			}
		}
		$self->dbClose();
	}

	if( $mode =~ /ROWS/i ) {
		return scalar (@retList);
	} else { 
		return @retList;
	}
}

sub listItems {
	my $self = shift;
	my $keys = { @_ };

	my $dataType   = $keys->{DATATYPE};
	my $from       = $keys->{FROM};
	my $maxItems   = $keys->{ITEMS};
	my $mode       = $keys->{MODE};

	my ( @ret, $key, $val, $cursor, $cnt, $dbstat, $flags, $item );

	return $self->setError (2167011, "OpenCA::DB->listItems: There is no datatype specified.")
		if( not $dataType );

	my ( $baseType, $status ) = $self->parseDataType( $dataType );
	if ($dataType eq $baseType) {
		$status = "VALID" if ( $baseType =~ /CERTIFICATE|CRL/ );
		$status = "PENDING" if ( $baseType =~ /REQUEST|CRR/ );
		$dataType = $status."_".$baseType; 
	}

	return $self->setError (2167021, "OpenCA::DB->listItems: Cannot open database ($errno)\n$errval")
		if (not $self->dbOpen( DATATYPE=>$dataType));

	if( $from > 0 ) {
		$flags = R_CURSOR; $key = $from;
	} else {
		$flags = R_FIRST; $key = ""; $val = "";
	}

	$cnt = 1;
	for ( $dbstat = $self->{dbms}->seq($key, $val, $flags ) ;
	      $dbstat == 0 ;
	      $dbstat = $self->{dbms}->seq($key, $val, R_NEXT )) {
		## Fetch results, different from the ELEMENTS key ...
		next if ($key eq "ELEMENTS");

		if ( $mode ne "RAW" ) {
			## Create Object if mode != "RAW"
			if( $item = $self->createObject(DATATYPE=>$dataType,
								DATA=>$val) ) {
				$item->getParsed()->{DBKEY} = $key;
				push( @ret, $item );
			}
		} else {
			push( @ret, $val );
		}

		$cnt++;
		last if ( $maxItems and $cnt > $maxItems );
	}

	return ( @ret );
}

sub createObject {
	my $self = shift;
	my $keys = { @_ };

	my $dataType   = $keys->{DATATYPE};
	my $rawData    = $keys->{DATA};

	my ( $obj );
	my ( $baseType, $status ) = $self->parseDataType( $dataType );

	return $self->setError (2143011, "OpenCA::DB->createObject: Cannot determine basetype ($errno)\n$errval")
		if( not $baseType );

	if( $baseType =~ /CERTIFICATE/ ) {
		$obj = new OpenCA::X509 ( SHELL=>$self->{backend},
					  DATA=>$rawData,
					  FORMAT=>$self->{defInFormat} );
	} elsif ( $baseType =~ /CRL/ ) {
		$obj = new OpenCA::CRL ( SHELL=>$self->{backend},
					 DATA=>$rawData,
					 FORMAT=>$self->{defInFormat} );
	} elsif ( $baseType =~ /REQUEST|CRR/ ) {
		$obj = new OpenCA::REQ ( SHELL=>$self->{backend},
					 DATA=>$rawData );
	} else {
		## Unrecognized object
		return $self->setError (2143021, "OpenCA::DB->createObject: Cannot determine the objecttype.");
	}

	return $obj;
}

sub getSignature {
        my $self = shift;
        my $obj  = shift;

	return $obj->getParsed()->{SIGNATURE};
}

sub getBody {
        my $self = shift;
        my $obj = shift;

	return $obj->getParsed()->{BODY};
}

sub getHeader {
        my $self = shift;
        my $obj = shift;

        my $beginHeader         = $self->{beginHeader};
        my $endHeader           = $self->{endHeader};

	my ( $ret, $pHead );

	$pHead = $obj->getParsed()->{HEADER};
	return $self->setError (2173011, "OpenCA::DB->getHeader: The object has no header.")
		if( not $pHead );

	$ret = "$beginHeader\n";
	foreach ( keys %$pHead ) {
		$ret .= "$_=" . $pHead->{$_} . "\n";
	}
	$ret .= "$endHeader\n";

        return $ret;
}

sub compareNumeric {
	my ( $k1, $k2 ) = @_ ;

	return $k1 <=> $k2;
}

sub compareString {
	my ( $k1, $k2 ) = @_ ;

        ## these are hashes
        ## --> these are really big hexadecimal numbers
        "\L$k1" <=> "\L$k2" ;
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
