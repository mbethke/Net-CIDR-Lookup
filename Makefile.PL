use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::CIDR::Lookup',
    AUTHOR              => 'Matthias Bethke <matthias@towiski.de>',
    VERSION_FROM        => 'lib/Net/CIDR/Lookup.pm',
	 #ABSTRACT_FROM       => 'lib/Net/CIDR/Lookup.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'Test::Class' => 0,
        'Bit::Vector' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-CIDR-Lookup-*' },
);
