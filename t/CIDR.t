#!/usr/bin/perl

use strict;
use warnings;
use Test::Class;

use lib 't/lib';

use Net::CIDR::Lookup::Test;
use Net::CIDR::Lookup::Tie::Test;
#use Net::CIDR::Lookup::IPv6::Test;

Test::Class->runtests;

