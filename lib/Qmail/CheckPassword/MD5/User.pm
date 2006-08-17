package Qmail::CheckPassword::MD5::User;

use strict;
use Digest::MD5 qw[md5_hex];
use vars        qw[@ISA];

use         Qmail::CheckPassword::User;
@ISA = qw[  Qmail::CheckPassword::User];

sub pass {
    my $self = shift;
    if(@_) {
        $self->{pass} = md5_hex(+shift);
    }
    return $self->{pass};
}           

1;
