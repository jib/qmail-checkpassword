#!/usr/bin/perlc

use strict;
use warnings;

use User::pwent;
use Unix::Syslog qw(:macros :subs);
use Digest::MD5 qw(md5_hex);
use Data::Dumper;


###
### Change these to match your system/site polices.
###

my $MINUID  = 100;       # We don't want brute force attacks against root, etc.
my $EGID    = "100 100"; # Don't pass extra groups like wheel, etc.
my $RGID    = 100;       
my $PWFILE  = '/var/qmail/users/md5-passwd';
my $DEBUG   = 1;

my $Ipaddr  = $ENV{'TCPREMOTEIP'};
my $Port    = $ENV{'TCPLOCALPORT'};
   
### MAIN ###   

$| = 1;
%ENV = ();
    
openlog( "$0: ", LOG_PID, LOG_MAIL );

my($user,   $pass)  = get_user_pass();
my $stored          = parse_passes( $user );

my $copy = $pass;
my $md5  = md5_hex($copy);
if( $md5 eq $stored ) {
    log_pop3($user);
    exec @ARGV;
} else {
    err_badpass($user,$pass);
}

sleep(10);
exit(-4);

### SUBS ###

sub get_user_pass {
    my($len,$buf);
    
    open my $fh, "<&=3" or exit (-3);
    $len = read $fh, $buf, 512;
    close $fh;
   
    exit(-3) if $len < 4;

    my ($user, $pass) = split /\x00/, $buf;
    $user = lc $user;
    $buf = "\x00" x $len;

    return ($user, $pass);
}

sub parse_passes {
    my $user = shift;

    my $pw = getpwnam($user) || err_unknown($user);

    exit(-4) unless $pw->uid;

    my %info = get_info_from_file($user);

    $ENV{'UID'}     = $> = $< = $pw->uid+0;
    $ENV{'USER'}    = $info{real};
    $ENV{'HOME'}    = $pw->dir;
    $ENV{'SHELL'}   = $pw->shell;      
    $)              = $EGID;
    $(              = $RGID;

    err_minuid($user) if $> < $MINUID;

    chdir $pw->dir;
    
    logit(  "user: %s, pass: %s, md5: %s, have %s, real: %s",
            [$user,$pass,md5_hex($pass),$info{pass}, $info{real}] ) if $DEBUG;

    return $info{pass};
}

sub get_info_from_file {
    my $user = shift;
    
    open my $fh, "$PWFILE" or exit(-3);
    
    my @list =  map  { @$_ }
                grep { lc($_->[0]) eq lc $user } 
                map  { chomp; [split ':'] } <$fh>;
    
    my %hash;
    @hash{qw|login pass real|} = @list; 
    $hash{real} = $hash{login} unless defined $hash{real};
    
    return %hash;
}

sub logit {
    my $msg     = shift or return;
    my @content = @{+shift};
    my $fatal   = shift || 0;
    
    syslog( LOG_INFO, $msg, @content );
    
    exit(-3) if $fatal;
}    

sub err_minuid {
    logit(  "Attempt to login port %d with UID lt %d (%s) from [%s]",
            [$Port, $MINUID, $user, $Ipaddr], 1);
}

sub err_badpass {
    my($user,$md5) = @_;
    logit(  "Attempt to login port %d failed for UID %d (%s - %s) from [%s] ",
            [$Port, $>, $user, $md5, $Ipaddr], 1);
}        

sub err_unknown {
    my $user = shift;
    logit(  "Attempt to login port %d with unknown user (%s) from [%s]", 
            [$Port, $user, $Ipaddr], 1);
}        
        
sub log_pop3 {
    my $user = shift;
    logit(  "port %d login successful UID %d (%s) from [%s]",
            [$Port, $>, $user, $Ipaddr] );
}


END {
    closelog;
}
