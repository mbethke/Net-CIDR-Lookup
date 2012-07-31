#!/usr/bin/perl
use strict;
use warnings;
use Test::Class;
use lib 't/lib';
use Net::CIDR::Lookup::Tie::Test;
Test::Class->runtests;

