package Net::CIDR::Lookup::IPv6::Test;

use strict;
use warnings;

use base 'Test::Class';
use Test::More;
use Test::Exception;
use Net::CIDR::Lookup::IPv6;

#-------------------------------------------------------------------------------

sub check_methods : Test(startup => 8) {
    my $t = Net::CIDR::Lookup::IPv6->new;
    can_ok($t,'add');
    can_ok($t,'add_num');
    can_ok($t,'add_range');
    can_ok($t,'lookup');
    can_ok($t,'lookup_num');
    can_ok($t,'clear');
    can_ok($t,'dump');
    can_ok($t,'walk');
}

sub before : Test(setup) {
    my $self = shift;
    $self->{tree} = Net::CIDR::Lookup::IPv6->new;
}

#-------------------------------------------------------------------------------

sub add : Tests(5) {
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('2001:db8::/32', 42) }, 'add() succeeded');
    lives_ok(sub { $t->add('2002:db8::/31', 23) }, 'add() succeeded');
    is($t->lookup('2001:db8::1234'), 42, 'Block 2001:db8::/32 lookup OK');
    is($t->lookup('2002:db8:1::'), 23, 'Block 2002:db8::/31 lookup OK');
    is($t->lookup('::1'), undef, 'No result outside blocks');
}

1;
__END__

sub add_range : Tests(6) {
    my $self = shift;
    my $t = $self->{tree};
    is($t->add_range('192.168.0.130-192.170.0.1', 42), 1, 'add_range() succeeded');
    is($t->add_range('1.3.123.234 - 1.3.123.240', 23), 1, 'add_range() succeeded');
    is($t->lookup('192.169.0.22'), 42, 'Range 192.168.0.130 - 192.170.0.1');
    is($t->lookup('1.3.123.235'),  23, 'Range 1.3.123.234 - 1.3.123.240');
    is($t->lookup('2.3.4.5'), undef, 'No result outside blocks');
    my $h = $t->dump;
    is(scalar keys %$h, 19, 'Range expansion: number of keys');
}

sub collision : Tests(2) {
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('192.168.0.129/25', 42) }, 'add() succeeded');
    isnt($t->add('192.168.0.160/31', 23), 1, 'add() failed as expected');
    # TODO errstr?
}

sub benign_collision : Test(3){
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('192.168.0.129/25', 42) }, 'add() succeeded');
    lives_ok(sub { $t->add('192.168.0.160/31', 42) }, 'add() succeeded');
    is($Net::CIDR::Lookup::errstr, undef, 'Benign CIDR block collision');
}

sub merger : Tests(4) {
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('192.168.0.130/25', 42) }, 'add() succeeded');
    is($t->add('192.168.0.0/25', 42),   1, 'add() succeeded');
    my $h = $t->dump;
    is(scalar keys %$h, 1, 'Merged block: number of keys');
    my ($k,$v) = each %$h;
    is($k, '192.168.0.0/24', 'Merged block: correct merged net block');
}

sub nonmerger : Tests(3) {
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('192.168.0.130/25', 42) }, 'add() succeeded');
    is($t->add('192.168.0.0/25', 23),   1, 'add() succeeded');
    my $h = $t->dump;
    is(scalar keys %$h, 2, 'Unmerged adjacent blocks: correct number of keys');
}

sub equalrange : Tests(4) {
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('192.168.0.130/25', 1) }, 'add() succeeded');
    lives_ok(sub { $t->add('192.168.0.130/25', 1) }, 'add() succeeded');
    my $h = $t->dump;
    is(0+keys %$h, 1, 'Got single block from two equal inserts');
    is($h->{'192.168.0.128/25'}, 1, 'Got correct block');
}

sub subrange1 : Tests(4) {
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('192.168.0.1/24', 1) }, 'add() range succeeded');
    lives_ok(sub { $t->add('192.168.0.1/25', 1) }, 'add() subrange succeeded');
    my $h = $t->dump;
    is(0+keys %$h, 1, 'Got single block from range followed by one of its immediate subranges');
    is($h->{'192.168.0.0/24'}, 1, 'Got correct block');
}

sub subrange2 : Tests(4) {
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('192.168.0.1/24', 1) }, 'add() range succeeded');
    lives_ok(sub { $t->add('192.168.0.1/28', 1) }, 'add() subrange succeeded');
    my $h = $t->dump;
    is(0+keys %$h, 1, 'Got single block from range followed by a small subrange');
    is($h->{'192.168.0.0/24'}, 1, 'Got correct block');
}

sub superrange1 : Tests(4) {
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('192.168.0.128/25', 1) }, 'add() range succeeded');
    is($t->add('192.168.0.0/24', 1), 1,   'add() superrange succeeded');
    my $h = $t->dump;
    is(0+keys %$h, 1, 'Got single block from range followed by its superrange');
    is($h->{'192.168.0.0/24'}, 1, 'Got correct block');
}

sub superrange2 : Tests(4) {
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('192.168.160.128/25', 1) }, 'add() range succeeded');
    lives_ok(sub { $t->add('192.168.160.0/20', 1) }, 'add() superrange succeeded');
    my $h = $t->dump;
    is(0+keys %$h, 1, 'Got single block from range followed by one of its higher superranges');
    is($h->{'192.168.160.0/20'}, 1, 'Got correct block');
}

sub clear : Tests(2) {
    my $self = shift;
    my $t = $self->{tree};
    lives_ok(sub { $t->add('192.168.0.129/25', 42) }, 'add() succeeded');
    $t->clear;
    is(scalar keys %{$t->dump}, 0, 'Reinitialized tree');
}

1;

