#!perl -T

use Test::More tests => 2;

BEGIN {
	use_ok( 'Net::CIDR::Lookup' );
	use_ok( 'Net::CIDR::Lookup::Tie' );
}

diag( "Testing Net::CIDR::Lookup $Net::CIDR::Lookup::VERSION, Perl $], $^X" );
diag( "Testing Net::CIDR::Lookup::Tie $Net::CIDR::Lookup::Tie::VERSION, Perl $], $^X" );
