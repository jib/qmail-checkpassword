#!/usr/bin/perlc -w

use strict;
use lib '../lib';
use lib '../../log-message/lib';
use GetOpt::Long;

use Qmail::CheckPassword;
my $qmail = Qmail::CheckPassword->new( '../etc/cpw.rc' );
my($user, $pass) = @ARGV;

my $ok = $qmail->validate($user,$pass);

print $ok ? "OK " : "NOK ";
print "$user\n";
