=head1 NAME

Net::CIDR::Lookup::IPv6

=head1 DESCRIPTION

This is the IPv6 version of L<Net::CIDR::Lookup>. It generally offers the same methods but with the following differences:

=over 1

=item * The C<add_num>/C<add_num_range> methods that accept an IPv4 address as
an integer have been split in two:

=over 1

=item * C<add_vec>/C<add_vec_range> accepts a 128-bit L<Bit::Vector> object for an address

=item * C<add_str>/C<add_str_range> takes a packed string as returned by C<Socket::unpack_sockaddr_in6>

=back

=item * The API does not use return values and a global C<$errstr> variable to
signal success or failure but raises an exception (i.e. dies with a message) on
error.

=back

=head1 HISTORY

=over 1

=item v0.4 First CPAN release

=back

=head1 METHODS

=cut

package Net::CIDR::Lookup::IPv6;
use strict;
use warnings;
use Carp;
use Socket qw/ getaddrinfo unpack_sockaddr_in6 inet_ntop AF_INET6 /;
use Bit::Vector;
use parent 'Net::CIDR::Lookup';

our $VERSION = sprintf "%d.%d", q$Revision: 0.4$ =~ m/ (\d+) \. (\d+) /xg;

=head2 add

Arguments: C<$cidr>, C<$value>

Return Value: none; dies on error

Adds VALUE to the tree under the key CIDR. CIDR must be a string containing an
IPv6 address followed by a slash and a number of network bits. Bits to the
right of this mask will be ignored.

=cut

sub add {
	my ($self, $cidr, $val) = @_;

    defined $val or croak "can't store an undef";
	my ($net, $bits) = $cidr =~ m{ ^ (.+) / (\d+) $ }ox;
    defined $net and defined $bits or croak 'CIDR syntax error: use <address>/<netbits>';
    $net = _parse_address($net);
	$self->_add($net, $bits, $val);
}

=head2 add_range

Arguments: C<$range>, C<$value>

Return Value: none; dies on error

Adds VALUE to the tree for each address included in RANGE which must be a
hyphenated range of IPv6 addresses and with the first address being numerically
smaller the second. This range will be split up into as many CIDR blocks as
necessary (algorithm adapted from a script by Dr. Liviu Daia).

=cut

sub add_range {
    my ($self, $range, $val) = @_;

    defined $val or croak "can't store an undef";
    my ($start, $end, $crud) = split /\s*-\s*/, $range;
    croak 'must have exactly one hyphen in range'
        if(defined $crud or not defined $end);
    $self->add_vec_range(_parse_address($start), _parse_address($end), $val);
}

=head2 add_vec

Arguments: C<$address>, C<$bits>, C<$value>

Return Value: none; dies on error

Like C<add()> but accepts an address as a Bit::Vector object and the network
bits as a separate integer instead of all in one string.

=cut

sub add_vec {   ## no critic (Subroutines::RequireArgUnpacking)
    # my ($self, $ip, $bits, $val) = @_;
	# Just call the recursive adder for now but allow for changes in object
    # representation ($self != $n)
    defined $_[3] or croak "can't store an undef";
	_add(@_);
}

=head2 add_str

Arguments: C<$address>, C<$bits>, C<$value>

Return Value: none; dies on error

Like C<add_vec()> but accepts an address as a packed string as returned by
C<Socket::unpack_sockaddr_in6>.

=cut

sub add_str {   ## no critic (Subroutines::RequireArgUnpacking)
    # my ($self, $ip, $bits, $val) = @_;
	shift->_add_vec(_str2vec($_[0]), _str2vec($_[1]), $_[2]);
}


=head2 add_vec_range

Arguments: C<$start>, C<$end>, C<$value>

Return Value: none; dies on error

Like C<add_range()> but accepts addresses as separate Bit::Vector objects
instead of a range string.

=cut

sub add_vec_range {
    my ($self, $start, $end, $val) = @_;
    my @chunks;

    1 == $start->Lexicompare($end)
        and croak sprintf "start > end in range %s--%s", _addr2print($start), _addr2print($end);

    _do_chunk(\@chunks, $start, $end, 127, 0);
    $self->add_vec(@$_, $val) for(@chunks);
}

=head2 add_str_range

Arguments: C<$start>, C<$end>, C<$value>

Return Value: true for successful completion; dies on error

Like C<add_vec_range()> but accepts addresses as packed strings as returned by
Socket::unpack_sockaddr_in6.

=cut

sub add_str_range { ## no critic (Subroutines::RequireArgUnpacking)
    # my ($self, $start, $end, $val) = @_;
    shift->add_vec_range(_str2vec($_[0]), _str2vec($_[1]), $_[2]);
}

=head2 lookup

Arguments: C<$address>

Return Value: value assoiated with this address or C<undef>

Looks up an IPv6 address specified as a string and returns the value associated
with the network containing it. So far there is no way to tell which network
that is though.

=cut

sub lookup {
	my ($self, $addr) = @_;

    # Make sure there is no network spec tacked onto $addr
    $addr =~ s!/.*!!;
	my $ip = _parse_address($addr);
	$self->_lookup($ip);
}


=head2 lookup_vec

Arguments: C<$address>

Return Value: value assoiated with this address or C<undef>

Like C<lookup()> but accepts the address as a Bit::Vector object.

=cut

sub lookup_vec { _lookup($_[0]) }   ## no critic (Subroutines::RequireArgUnpacking)

=head2 lookup_str

Arguments: C<$address>

Return Value: value assoiated with this address or C<undef>

Like C<lookup()> but accepts the address as a packed string as returned by
C<Socket::unpack_sockaddr_in6>.

=cut

sub lookup_str { _lookup(_str2vec($_[0])) }   ## no critic (Subroutines::RequireArgUnpacking)

=head2 dump

Arguments: none

Return Value: C<$hashref>

Returns a hash representation of the tree with keys being CIDR-style network
addresses.

=cut

sub dump {  ## no critic (Subroutines::ProhibitBuiltinHomonyms)
	my ($self) = @_;
	my %result;
	$self->_walk(Bit::Vector->new(128), 0, sub {
            my ($addr, $bits, $val) = @_;
            my $net = _addr2print($_[0]) . '/' . $_[1];
            if(defined $result{$net}) {
                confess "internal error: network $net mapped to $result{$net} already!";
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

The network address as a Bit::Vector object. The callback must not change this
object's contents, use $addr->Clone if in doubt!

=item C<$bits>

The current CIDR block's number of network bits

=item C<$value>

The value associated with this block

=back

Return Value: nothing useful

=cut

sub walk { $_[0]->_walk(Bit::Vector->new(128), 0, $_[1]) }   ## no critic (Subroutines::RequireArgUnpacking)

=head1 BUGS

=over 1

=item * The IPv6 version hasn't seen any real-world testing and the unit tests
are still rather scarce, so there will probably be more bugs than listed here.

=item * I didn't need deletions yet and deleting parts of a CIDR block is a bit more
complicated than anything this class does so far, so it's not implemented.

=item * Storing an C<undef> value does not work and yields an error. This would be
relatively easy to fix at the cost of some memory so that's more a design
decision.

=item * A consequence of the same design is also that a /0 block can't be formed.
Although it doesn't make much sense, this might happen if your input is that
weird.

=back

=head1 AUTHORS, COPYRIGHTS & LICENSE

Matthias Bethke <matthias@towiski.de>

Licensed unter the Artistic License 2.0

=head1 SEE ALSO

This module's methods are based even more loosely than those of L<Net::CIDR::Lookup> on those of L<Net::CIDR::Lite>

=cut

# Walk through a subtree and insert a network
sub _add {
	my ($node, $addr, $nbits, $val) = @_;
    my ($bit, $checksub);
    my @node_stack;

    DESCEND:
    while(1) {
	    $bit = $addr->shift_left(0);

        if(__PACKAGE__ ne ref $node) {
            return 1 if $val eq $node; # Compatible entry (tried to add a subnet of one already in the tree)
            croak "incompatible entry, found `$node' trying to add `$val'";
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
    
    $checksub
        and defined $node->[$bit]
        and __PACKAGE__ eq ref $node->[$bit]
        and _add_check_subtree($node->[$bit], $val);

    $node->[$bit] = $val;

    # Take care of potential mergers into the previous node (if $node[0] == $node[1])
    # TODO recursively check upwards
    not @node_stack
        and defined $node->[$bit ^ 1]
        and $node->[$bit ^ 1] eq $val
        and croak 'merging two /1 blocks is not supported yet';
    while(1) {
        $node = pop @node_stack // last MERGECHECK;
        last unless(defined $$node->[0] and defined $$node->[1] and $$node->[0] eq $$node->[1]);
        $$node = $val;
    }
}

# Check an existing subtree for incompatible values. Returns false and sets the
# package-global error string if there was a problem.
sub _add_check_subtree {
    my ($root, $val) = @_;

    eval {
        $root->_walk(Bit::Vector->new(128), 0, sub {
                my $oldval = $_[2];
                $val == $oldval or die $oldval; ## no critic (ErrorHandling::RequireCarping)
            }
        );
        1;
    } or do {
        $@ and croak "incompatible entry, found `$@' trying to add `$val'";
    };
}

sub _lookup {
	my ($node, $addr) = @_;

    my $bit = $addr->shift_left(0);
	defined $node->[$bit] or return;
	__PACKAGE__ ne ref $node->[$bit] and return $node->[$bit];
	_lookup($node->[$bit], $addr);
}

# Convert a packed IPv6 address to a Bit::Vector object
sub _str2vec {   ## no critic (Subroutines::RequireArgUnpacking)
    my $b = Bit::Vector->new(128);
    $b->Chunk_List_Store(32, reverse unpack 'N4', $_[0]);
    return $b;
}

# Parse an IPv6 address and return a Bit::Vector object
sub _parse_address {   ## no critic (Subroutines::RequireArgUnpacking)
    my ($err, @result) = getaddrinfo($_[0], 0);
    $err and croak "Error parsing address ($_[0]): $err";
    # Some of this could be replaced by _str2vec but isn't for speed
    my $b = Bit::Vector->new(128);
    $b->Chunk_List_Store(32, reverse unpack 'N4', (unpack_sockaddr_in6 $result[0]{addr})[1]);
    return $b;
}

# Convert a Bit::Vector object holding an IPv6 address to a printable string
sub _addr2print { inet_ntop(AF_INET6, pack('N4', reverse $_[0]->Chunk_List_Read(32))) }   ## no critic (Subroutines::RequireArgUnpacking)

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
    $addr->Bit_On(128 - $bits);
	if(__PACKAGE__ eq ref $b) {
		$b->_walk($addr, $bits, $cb);
	} else {
		defined $b and $cb->($addr, $bits, $b);
	}
}

# Split a chunk into a minimal number of CIDR blocks.
sub _do_chunk {
    my ($chunks, $start, $end, $ix1, $ix2) = @_;
    my ($xor, $lowbits, $prefix, $tmp_prefix) = Bit::Vector->new(128, 4);

    # Find common prefix.  After that, the bit indicated by $ix1 is 0 for $start
    # and 1 for $end. A split a this point guarantees the longest suffix.
    $xor->Xor($start, $end);
    #print "--------------------------------------------------------------------------------\n";
    #print "Start : ",$start->to_Hex,"\n";
    #print "End   : ",$end->to_Hex,"\n";
    #print "XOR   : ",$xor->to_Hex,"\n";
    --$ix1 until($xor->bit_test($ix1) or -1 == $ix1);
    $prefix->Interval_Fill($ix1, 127);
    $prefix->And($prefix, $start);

    $ix2++ while($ix2 <= $ix1
            and not $start->bit_test($ix2)
            and $end->bit_test($ix2));

    #print "After loop: ix1=$ix1, ix2=$ix2, ";
    #print "Prefix: ",$prefix->to_Hex,"\n";

    # Split if $fbits and $lbits disagree on the length of the chunk.
    if ($ix2 <= $ix1) {
        #print "splitting\n";
        #print "Recursing with $ix1 lowbits=1 in end\n";
        $tmp_prefix->Copy($prefix);
        $tmp_prefix->Interval_Fill(0, $ix1-1);
        _do_chunk($chunks, $start, $tmp_prefix, $ix1, $ix2);

        #print "Recursing with $ix1 lowbits=0 in start\n";
        $tmp_prefix->Copy($prefix);
        $tmp_prefix->Bit_On($ix1);
        _do_chunk($chunks, $tmp_prefix, $end, $ix1, $ix2);
    } else {
        #print "not splitting\n";
        push @$chunks, [ $prefix, 127-$ix1 ];
        #printf "Result: %s/%d\n", $chunks->[-1][0]->to_Hex, $chunks->[-1][1];
    }
}

1;
