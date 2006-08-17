#!perl -w

package Qmail::CheckPassword;

use strict;
use Tools::Check;
use Module::Load;
use Log::Message;
use Config::Auto;
use Data::Dumper;

my $log = new Log::Message level => 'carp';

my $check_from = {
    md5     =>  {   module      => 'Qmail::CheckPassword::MD5',
                    location    => '/var/qmail/users/md5-passwd',
                    pretty      => 'MD5 check',
                    active      => 0,
                    order       => 1,
                },
#    master  => 1,
#    db      => 1,
#    pam     => 1,
#    nt      => 1,
#    afs     => 1,
};    

### overrides the defaults with whatever the user configured ###
sub _setup_config {
    my $self = shift;
    my $conf = shift;
    
    my $parsed  = Config::Auto::parse( $conf );
    
    for my $key ( qw|use| ) {
        my @list = ref $parsed->{$key} ? @{$parsed->{$key}} : ($parsed->{$key});
     
        ### so the user has some preferences about what to use ###   
        if( scalar @list ) {
        
            ### so turn everything off and let the user enable it ###
            for my $type ( keys %$check_from ) {
                $check_from->{$type}->{active} = 0;
            }
        }
        
        ### loop over all the things he wanted to use ###      
        my $i = 0;
        for my $type (@list) {
        
            BLOCK: {    
                my $href = $check_from->{$type} || {};
                warn Dumper $href;
                ### is it one we originally support ? ###
                my $org = keys %$href;                
                
                ### check for differing implementations than the default ###
                for my $extra ( qw|module location| ) {
                    my $name = $extra.'_'.$type;
                
                    my @opts = grep { defined && length } 
                                        ref $parsed->{$name} 
                                            ? @{$parsed->{$name}} 
                                            : ($parsed->{$name});
        
                    ### can only have one location or module, so warn if
                    ### more were specified 
                    if( scalar @opts > 1 ) {
                        $log->store(qq['$name' can only have one entry! First entry wins!]); 
                    
                    ### and disable this method if none were specified ###
                    } elsif ( scalar @opts < 1 ) {
                        $log->store(qq[No entry for '$name': cannot support '$type'])
                            unless $org;
                        $org ? next : last BLOCK;         
                    }
                    
                    $href->{$extra} = shift @opts;   
                }
            
                ### all is ok, activate it ###
                $href->{active} = 1;
                $href->{order} = ++$i;
            
                ### and replace the entry in the global conf ###
                $check_from->{$type} = $href;
            }
        }           
    }                
    return 1;
}        

sub new {
    my $class   = shift;
    my $config  = shift || '/etc/qmail-cpw.rc';
    
    my $self = bless { }, $class;
    
    $self->_setup_config( $config );

    return $self;
}    

sub validate {
    my $self = shift;
    my $user = shift or return;
    my $pass = shift or return;

    my @list =  sort { $a->{order} <=> $b->{order} } 
                grep { $_->{active} } values %$check_from;
    
    my $ok = 0;
    for my $href ( @list ) {
        my $class   = $href->{module};
        load $class;
        
        my $obj = $class->new( $href->{location} );                
        
        $ok = $obj->validate($user,$pass);
        
        $ok ? last : $log->store(qq[$href->{pretty} check failed]);
    }     

    return $ok;
}

sub alter {
    1;
}

sub show {
    1;
}

    
