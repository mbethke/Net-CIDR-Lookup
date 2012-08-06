use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::CIDR::Lookup',
    AUTHOR              => 'Matthias Bethke <matthias@towiski.de>',
    VERSION_FROM        => 'lib/Net/CIDR/Lookup.pm',
	ABSTRACT            => 'Hash-like lookup table based on CIDR blocks',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
#    PM                  => {
#        'lib/Net/CIDR/Lookup.pm'                => '$(INST_LIBDIR)/Lookup.pm',
#        'lib/Net/CIDR/Lookup/IPv6.pm'           => '$(INST_LIBDIR)/Lookup/IPv6.pm',
#        'lib/Net/CIDR/Lookup/Tie.pm'            => '$(INST_LIBDIR)/Lookup/Tie.pm',
#        'lib/Net/CIDR/Lookup/Changes.pod'       => '$(INST_LIBDIR)/Lookup/Changes.pod',
#        'lib/Net/CIDR/Lookup/IPv6/Changes.pod'  => '$(INST_LIBDIR)/Lookup/IPv6/Changes.pod',
#        'lib/Net/CIDR/Lookup/Tie/Changes.pod'   => '$(INST_LIBDIR)/Lookup/Tie/Changes.pod',
#    },
    PREREQ_PM => {
        'Test::More'  => 0,
        'Test::Class' => 0,
        'Bit::Vector' => 0,
        'Socket'      => 1.94,
    },
    dist                => { COMPRESS => 'bzip2', SUFFIX => 'bz', },
    clean               => { FILES => 'Net-CIDR-Lookup-*' },
);
