package Qmail::CheckPassword::MD5;
use strict;

use Tools::Check;
use Log::Message;
use FileHandle;
use File::Copy;

use Digest::MD5 qw[md5_hex];
use Qmail::CheckPassword::MD5::User;

my $log     = new Log::Message level => 'carp';
my $file    = new FileHandle;

### accessors ###
for my $key ( qw[users loc] ) {
    no strict 'refs';
    *{__PACKAGE__."::$key"} = sub {
        my $self = shift;
        $self->{$key} = $_[0] if @_;
        return $self->{$key};
    }
}

sub new {
    my $class   = shift;
    my $loc     = shift;

    $file->open("$loc") or (
        $log->store(qq[Couldn't open '$loc': $!] ),
        return
    );
    my $self = { loc => $loc };

    my %seen;
    while( <$file> ) {
        next if /^\s*#/;    # ignore comments
        next if $_ !~ /\S/; # blank line
        chomp;

        my %opts;
        @opts{sort qw[user pass realname path active modified]} = split ':';

        use Data::Dumper;
        warn Dumper \%opts;

        my $user = Qmail::CheckPassword::MD5::User->new( %opts ) or return;
        my $login = $user->user;

        $log->store(qq[User '$login' mentioned more than once! Last mention wins!])
            if $seen{$login}++;

        $self->{users}->{$user->user} = $user;
    }

    $file->close;

    return bless $self, $class;
}

sub details {
    my $self = shift;
    my $user = shift or return;

    my $obj = $self->users->{$user} or (
        $log->store(qq[No such user: '$user'] ),
        return
    );

    return $obj;
}

sub validate {
    my $self = shift;
    my $user = shift or return;
    my $pass = shift or return;

    my $obj = $self->details( $user ) or return;

    return $obj->pass eq md5_hex($pass) ? 1 : 0;
}

sub alter {
    my $self = shift;
    my %hash = @_;

    my $dummy   = Qmail::CheckPassword::MD5::User->new( %hash ) or return;
    my $obj     = $self->details( $dummy->user ) or return;

    for my $what ( $obj->accessors ) {
        next unless length $dummy->$what;
        $obj->$what( $dummy->$what );
    }

    return 1;
}

sub add {
    my $self = shift;
    my %hash = @_;

    my $user = Qmail::CheckPassword::MD5::User->new( %hash ) or return;

    my $users = $self->users;

    if( exists $users->{$user} ) {
        $log->store(qq[Can't add '$user': already exists!]),
        return;
    };

    $users->{ $user->user } = $user;

    $self->users($users);

    return 1;
}

sub save {
    my $self    = shift;
    my $loc     = $self->loc;

    copy( $loc, $loc.'~' ) or (
        $log->store(qq[Unable to back up current file '$loc': $!]),
        return
    );

    $file->open( ">$loc" ) or (
        $log->store(qq[Couldn't open '$loc' for writing: $!]),
        return
    );

    my @meths = Qmail::CheckPassword::User->accessors;
    $file->print( '# ', join ':', @meths );

    for my $obj ( values %{$self->users} ) {

        $file->print( join ':', ,map { $obj->$_ } @meths );
        $file->print("\n");
    }

    $file->close;

    return 1;
}

1;
