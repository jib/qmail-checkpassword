package Qmail::CheckPassword::User;

use strict;
use Tools::Check qw[check];
use Log::Message;

my $tmpl = {
    user        => { default => '', strict_type => 1, required => 1 },
    pass        => { default => '', strict_type => 1, required => 1 },
    realname    => { default => '', strict_type => 1, required => 1 },
    path        => { default => ''},
    active      => { default => undef },
    modified    => { default => scalar localtime },
};

my $log = new Log::Message level => 'carp';

for my $key ( keys %$tmpl ) {
    no strict 'refs';
    *{__PACKAGE__."::$key"} = sub {
        my $self = shift;
        $self->{$key} = $_[0] if @_;
        return $self->{$key};
    }
}

sub new {
    my $class   = shift;
    my %hash    = @_;
    
    my $args = check( $tmpl, \%hash, 1 ) or (
        $log->store(qq[Couldn't validate arguments]),
        return
    );
    
    return bless $args, $class;
}

sub accessors { return keys %$tmpl; }

1;    
