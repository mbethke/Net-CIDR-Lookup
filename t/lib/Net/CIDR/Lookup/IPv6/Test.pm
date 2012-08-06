package Net::CIDR::Lookup::IPv6::Test;

use strict;
use warnings;
use parent 'My::Test::Class';
use Test::More;
use Test::Exception;

#-------------------------------------------------------------------------------

sub check_methods : Test(startup => 8) {
    my $t = shift->class->new;
    can_ok($t,'add');
    can_ok($t,'add_num');
    can_ok($t,'add_range');
    can_ok($t,'lookup');
    can_ok($t,'lookup_num');
    can_ok($t,'clear');
    can_ok($t,'to_hash');
    can_ok($t,'walk');
}

sub before : Test(setup) {
    my $self = shift;
    $self->{tree} = $self->class->new;
}

sub _needs_ipv6 : Test(setup) {
    shift->SKIP_ALL('needs IPv6 support in Socket module')
    unless defined eval { Socket::AF_INET6() };
}
#-------------------------------------------------------------------------------

sub add : Tests(3) {
    my $t = shift->{tree};
    $t->add('2001:db8::/32', 42);
    $t->add('2002:db8::/31', 23);
    is($t->lookup('2001:db8::1234'), 42, 'Block 2001:db8::/32 lookup OK');
    is($t->lookup('2002:db8:1::'), 23, 'Block 2002:db8::/31 lookup OK');
    is($t->lookup('::1'), undef, 'No result outside blocks');
}

sub add_range : Tests(4) {
    my $t = shift->{tree};
    $t->add_range('2001:db8::-2003:db8::abc', 42);
    $t->add_range('1::1234 - 1::1:2345', 23);
    is($t->lookup('2002:cb8::abc'),  42, 'Range 2001:db8::--2002:db8::abc OK');
    is($t->lookup('1::ffff'), 23, 'Range 1::1234--1::1:2345 OK');
    is($t->lookup('f::'), undef, 'No result outside blocks');
    my $h = $t->to_hash;
    is(scalar keys %$h, 39, 'Range expansion: number of keys');
}

1;
