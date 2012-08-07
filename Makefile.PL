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
    PREREQ_PM => {
        'Bit::Vector' => 0,
        'Socket'      => 1.94,
    },
    BUILD_REQUIRES => {
        'Test::More'                => 0,
        'Test::Class'               => 0,
        'Class::Data::Inheritable'  => 0,
    },
    dist                => { COMPRESS => 'bzip2', SUFFIX => 'bz', },
    clean               => { FILES => 'Net-CIDR-Lookup-*' },
);
