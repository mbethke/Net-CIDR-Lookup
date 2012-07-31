#!/usr/bin/perl

use strict;
use warnings;
use Test::Class;
use lib 't/lib';
use Net::CIDR::Lookup::Test;
Test::Class->runtests;

