use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'OpenCA::DB',
    'VERSION_FROM' => 'DB.pm', # finds $VERSION
#    'MAN3PODS'     => {'DB.pod'},
    'PREREQ_PM'    => {
                       'OpenCA::REQ'     => '0.9',
                       'OpenCA::X509'    => '0.9',
                       'OpenCA::CRL'     => '0.9',
                       'OpenCA::OpenSSL' => '0.9',
                       'OpenCA::Tools'   => '0.4',
                       'DB_File'         => '1.8'
                      }
);
