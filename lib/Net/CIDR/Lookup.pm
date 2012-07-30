=head1 NAME

Net::CIDR::Lookup

=head1 DESCRIPTION

This class implements a lookup table indexed by IPv4 networks or hosts.

=over 1

=item * Addresses are accepted in numeric form (integer with separate netbits argument),
as strings in CIDR notation or as IP address ranges

=item * Overlapping or adjacent networks are automatically coalesced if their
associated values are equal.

=item * The table is implemented as a binary tree so lookup and insertion take O(log n)
time.

=back

Methods generally return a true value on success and C<undef> on error. In the
latter case, an error message will be available in C<$Net::CIDR::Lookup::errstr>

=head1 SYNOPSIS

  use Net::CIDR::Lookup;

  $cidr = Net::CIDR::Lookup->new;
  $cidr->add("192.168.42.0/24",1);    # Add first network, value 1
  $cidr->add_num(167772448,27,2);     # 10.0.1.32/27 => 2
  $cidr->add("192.168.43.0/24",1);    # Automatic coalescing to a /23
  $cidr->add("192.168.41.0/24",2);    # Stays separate due to different value
  $cidr->add("192.168.42.128/25",2);  # Error: overlaps with different value

  $h = $cidr->dump;                   # Convert tree to a hash

  print "$k => $v\n" while(($k,$v) = each %$h);

  # Output (order may vary):
  # 192.168.42.0/23 => 1
  # 10.0.1.32/27 => 2
  # 192.168.41.0/24 => 2

  $cidr->walk(sub {
      my ($addr, $bits, $val) = @_;
      print join('.', unpack 'C*', pack 'N', $addr), "/$bits => $val\n"
    }
  );

  # Output (fixed order):
  # 10.0.1.32/27 => 2
  # 192.168.41.0/24 => 2
  # 192.168.42.0/23 => 1

  $cidr->clear;                                 # Remove all entries
  $cidr->add_range('1.2.3.11 - 1.2.4.234', 42); # Add a range of addresses, automatically split into CIDR blocks
  $h = $cidr->dump;
  print "$k => $v\n" while(($k,$v) = each %$h);

  # Output (order may vary):
  # 1.2.4.128/26 => 42
  # 1.2.3.32/27 => 42
  # 1.2.3.64/26 => 42
  # 1.2.4.234/32 => 42
  # 1.2.4.0/25 => 42
  # 1.2.3.12/30 => 42
  # 1.2.3.128/25 => 42
  # 1.2.3.16/28 => 42
  # 1.2.4.224/29 => 42
  # 1.2.4.232/31 => 42
  # 1.2.3.11/32 => 42
  # 1.2.4.192/27 => 42

=head1 HISTORY

=over 1

=item v0.3 First CPAN release

=item v0.3.1 

=over 1

=item * Replaced the simplistic list-based CIDR block splitting function with bit-fiddling for about a threefold speedup of C<add_num_range> and slightly less in C<add_range>.

=item * Recursive merging-up up of blocks during C<add_*> works now. If e.g.
you had a /24 and an adjacent /25 net with the same value before, adding a new
/25 would have merged the new block with the existing /25, resulting in two
adjacent /24s with the same value because only single-level merging was
possible. Now the two will be merged to a single /23.

=item * Removed some redundant tests and added new ones.

=item * Removed some leftover debug code.

=item * Some small fixes/improvements like stricter range checking in C<add_range>

=back

=item v0.4

=over 1

=item * Version bump for inclusion of the IPv6 version

=back

=back

=head1 METHODS

=cut

package Net::CIDR::Lookup;
use strict;
use warnings;
use Carp;

our $VERSION = sprintf "%d.%d", q$Revision: 0.4$ =~ m/ (\d+) \. (\d+) /xg;
our $errstr  = undef;

=head2 new

Arguments: none

Return Value: new object

=cut

sub new { bless [], shift }

=head2 add

Arguments: C<$cidr>, C<$value>

Return Value: true for successful completion, C<undef> otherwise

Adds VALUE to the tree under the key CIDR. CIDR must be a string containing an
IPv4 address followed by a slash and a number of network bits. Bits to the
right of this mask will be ignored.

=cut

sub add {
	my ($self, $cidr, $val) = @_;

    unless(defined $val) {
        $__PACKAGE__::errstr = "can't store an undef";
        return;
    }
	my ($net, $bits) = $cidr =~ m{ ^ ([.[:digit:]]+) / (\d+) $ }ox;
    unless(defined $net and defined $bits) {
        $__PACKAGE__::errstr = 'full dotted-quad/netbits notation required';
        return;
    }
    my $intnet = _dq2int($net) or return;
	$self->_add($intnet,$bits,$val);
}

=head2 add_range

Arguments: C<$range>, C<$value>

Return Value: true for successful completion, C<undef> otherwise

Adds VALUE to the tree for each address included in RANGE which must be a
hyphenated range of IP addresses in dotted-quad format (e.g.
"192.168.0.150-192.168.10.1") and with the first address being numerically
smaller the second. This range will be split up into as many CIDR blocks as
necessary (algorithm adapted from a script by Dr. Liviu Daia).

=cut

sub add_range {
    my ($self, $range, $val) = @_;

    unless(defined $val) {
        $__PACKAGE__::errstr = "can't store an undef";
        return;
    }

    my ($ip_start, $ip_end, $crud) = split /\s*-\s*/, $range;
    if(defined $crud or not defined $ip_end) {
        $__PACKAGE__::errstr = 'must have exactly one hyphen in range';
        return;
    }

    $ip_start = _dq2int($ip_start) or return;
    $ip_end   = _dq2int($ip_end)   or return;
    # This check will be repeated in add_num_range but we get more readable
    # errors here
    if($ip_start > $ip_end) {
        $__PACKAGE__::errstr = "start > end in range `$range'";
        return;
    }

    $self->add_num_range($ip_start, $ip_end, $val);
}

=head2 add_num

Arguments: C<$address>, C<$bits>, C<$value>

Return Value: true for successful completion, C<undef> otherwise

Like C<add()> but accepts address and bits as separate integer arguments
instead of a string.

=cut

sub add_num { ## no critic (Subroutines::RequireArgUnpacking)
    # my ($self,$ip,$bits,$val) = @_;
	# Just call the recursive adder for now but allow for changes in object
    # representation ($self != $n)
    unless(defined $_[3]) {
        $__PACKAGE__::errstr = "can't store an undef";
        return;
    }
	_add(@_);
}

=head2 add_num_range

Arguments: C<$start>, C<$end>, C<$value>

Return Value: true for successful completion, C<undef> otherwise

Like C<add_range()> but accepts addresses as separate integer arguments instead
of a range string.

=cut

sub add_num_range {
    my ($self, $start, $end, $val) = @_;

    if($start > $end) {
        $__PACKAGE__::errstr = "start > end in range $start--$end";
        return;
    }

    my @chunks;
    _do_chunk(\@chunks, $start, $end, 31, 0);
    foreach(@chunks) {
        $self->add_num(@$_, $val) or return;   # Immediately fail on first problem
    }
    1;
}

=head2 lookup

Arguments: C<$address>

Return Value: value assoiated with this address or C<undef>

Looks up an address and returns the value associated with the network
containing it. So far there is no way to tell which network that is though.

=cut

sub lookup {
	my ($self, $addr) = @_;

    # Make sure there is no network spec tacked onto $addr
    $addr =~ s!/.*!!;
	my $ip = _dq2int($addr) or return;
	$self->_lookup($ip, 32);
}


=head2 lookup_num

Arguments: C<$address>

Return Value: value assoiated with this address or C<undef>

Like C<lookup()> but accepts the address in integer form.

=cut

sub lookup_num { _lookup(@_, 32) } ## no critic (Subroutines::RequireArgUnpacking)

=head2 dump

Arguments: none

Return Value: C<$hashref>

Returns a hash representation of the tree with keys being CIDR-style network
addresses.

=cut

sub dump {  ## no critic (Subroutines::ProhibitBuiltinHomonyms)
	my ($self) = @_;
	my %result;
	$self->_walk(0, 0, sub {
            my $net = _int2dq($_[0]) . '/' . $_[1];
            if(defined $result{$net}) {
                confess("internal error: network $net mapped to $result{$net} already!\n");
            } else {
                $result{$net} = $_[2];
            }
        }
    );
	\%result;
}

=head2 walk

Arguments: C<$coderef> to call for each tree entry. Callback arguments are:

=over 1

=item C<$address>

The network address in integer form

=item C<$bits>

The current CIDR block's number of network bits

=item C<$value>

The value associated with this block

=back

Return Value: nothing useful

=cut

sub walk { $_[0]->_walk(0, 0, $_[1]) } ## no critic (Subroutines::RequireArgUnpacking)


=head2 clear

Arguments: none

Return Value: nothing useful

Remove all entries from the tree.

=cut

sub clear {
    my $self = shift;
    undef @$self;
}

=head1 BUGS

=over 1

=item *

I didn't need deletions yet and deleting parts of a CIDR block is a bit more
complicated than anything this class does so far, so it's not implemented.

=item *

Storing an C<undef> value does not work and yields an error. This would be
relatively easy to fix at the cost of some memory so that's more a design
decision.

=item *

Using a package-global for error reporting was an incredibly stupid idea
initially. This will change in the next version.

=back

=head1 AUTHORS, COPYRIGHTS & LICENSE

Matthias Bethke <matthias@towiski.de>
while working for 1&1 Internet AG

Licensed unter the Artistic License 2.0

=head1 SEE ALSO

This module's methods are based loosely on those of C<Net::CIDR::Lite>

=cut

# Walk through a subtree and insert a network
sub _add {
	my ($node, $addr, $nbits, $val) = @_;
    my ($bit, $checksub);
    my @node_stack;

    DESCEND:
    while(1) {
	    $bit = ($addr & 0x80000000) >> 31;
        $addr <<= 1;

        if(__PACKAGE__ ne ref $node) {
            return 1 if($val eq $node); # Compatible entry (tried to add a subnet of one already in the tree)
            $__PACKAGE__::errstr = "incompatible entry, found `$node' trying to add `$val'";
            return;
        }
        last DESCEND unless --$nbits;
        if(defined $node->[$bit]) {
            $checksub = 1;
        } else {
            $node->[$bit] ||= bless([], __PACKAGE__);
            $checksub = 0;
        }
        push @node_stack, \$node->[$bit];
        $node = $node->[$bit];
    }
    
    if($checksub and __PACKAGE__ eq ref $node->[$bit]) {
        _add_check_subtree($node->[$bit], $val) or return;
    }

    $node->[$bit] = $val;

    # Take care of potential mergers into the previous node (if $node[0] == $node[1])
    if(not @node_stack and defined $node->[$bit ^ 1] and $node->[$bit ^ 1] eq $val) {
        $__PACKAGE__::errstr = 'merging two /1 blocks is not supported yet';
        return;
    }
    while(1) {
        $node = pop @node_stack // last;
        last unless(defined $$node->[0] and defined $$node->[1] and $$node->[0] eq $$node->[1]);
        $$node = $val;
    }
    1;
}

# Check an existing subtree for incompatible values. Returns false and sets the
# package-global error string if there was a problem.
sub _add_check_subtree {
    my ($root, $val) = @_;

    eval {
        $root->_walk(0, 0, sub {
                my $oldval = $_[2];
                $val == $oldval or die $oldval; ## no critic (ErrorHandling::RequireCarping)
            }
        );
        1;
    } or do {
        if($@) {
            $__PACKAGE__::errstr = "incompatible entry, found `$@' trying to add `$val'";
            return;
        }
    };
    return 1;
}

sub _lookup {
	my ($node, $addr) = @_;

	my $bit = ($addr & 0x80000000) >> 31;
	defined $node->[$bit] or return;
	__PACKAGE__ ne ref $node->[$bit] and return $node->[$bit];
	_lookup($node->[$bit], $addr << 1);
}

# Dotted-quad to integer
sub _dq2int { ## no critic (Subroutines::RequireArgUnpacking)
	my @oct = split /\./, $_[0];
	unless(4 == @oct) {
        $__PACKAGE__::errstr = "address must be in dotted-quad form, is `$_[0]'";
        return;
    }
	my $ip = 0;
    foreach(@oct) {
        if($_ > 255 or $_ < 0) {
            $__PACKAGE__::errstr = "invalid component `$_' in address `$_[0]'";
            return;
        }
        $ip = $ip<<8 | $_;
    }
	$ip;
}

# Convert an IP address in integer format to dotted-quad
sub _int2dq { join '.', unpack 'C*', pack 'N', shift }

# Convert a CIDR block ($addr, $bits) into a range of addresses ($lo, $hi)
# sub _cidr2rng { ( $_[0], $_[0] | ((1 << $_[1]) - 1) ) }

# Walk the tree in depth-first LTR order
sub _walk {
	my ($node, $addr, $bits, $cb) = @_;
	my ($a, $b) = @$node;

	++$bits;
    # Check left side
	if(__PACKAGE__ eq ref $a) {
		$a->_walk($addr, $bits, $cb);
	} else {
		defined $a and $cb->($addr, $bits, $a);
	}
    # Check right side
	if(__PACKAGE__ eq ref $b) {
		$b->_walk($addr | 1 << 32-$bits, $bits, $cb);
	} else {
		defined $b and $cb->($addr | 1 << 32-$bits, $bits, $b);
	}
}

# Split a chunk into a minimal number of CIDR blocks.
sub _do_chunk {
    my ($chunks, $start, $end, $ix1, $ix2) = @_;
    my ($prefix, $xor);

    # Find common prefix.  After that, the bit indicated by $ix1 is 0 for $start
    # and 1 for $end. A split a this point guarantees the longest suffix.
    $xor = $start ^ $end;
    --$ix1 until($xor & 1 << $ix1 or -1 == $ix1);
    $prefix = $start & ~((1 << ($ix1+1)) - 1);

    $ix2++ while($ix2 <= $ix1
            and not ($start & 1 << $ix2)
            and     ($end   & 1 << $ix2));

    # Split if $fbits and $lbits disagree on the length of the chunk.
    if ($ix2 <= $ix1) {
        _do_chunk($chunks, $start,              $prefix | ((1<<$ix1) - 1), $ix1, $ix2);
        _do_chunk($chunks, $prefix | (1<<$ix1), $end,                      $ix1, $ix2);
    } else {
        push @$chunks, [ $prefix, 31-$ix1 ];
    }
}

1;
