#!/usr/bin/perl

=head1 NAME

File::KeePass::Agent - Commandline interface interface to KeePass V1 database files

=cut

File::KeePass::Agent::run(),exit if $0 eq __FILE__;

package File::KeePass::Agent;

use strict;
use warnings;
use Carp qw(croak);
use File::KeePass;

our @ISA;
BEGIN {
    my $os = lc($^O);
    if (! eval { require "File/KeePass/Agent/$os.pm" }) {
        croak "It appears that \"$os\" is not yet supported by ".__PACKAGE__.": $@";
    }
    @ISA = (__PACKAGE__."::$os");
}

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub run {
    my $self = ref($_[0]) ? shift() : __PACKAGE__->new;
    my $file = shift || shift(@ARGV) || $self->prompt_for_file || croak "Can't continue without kdb file";
    my $pass = shift || shift(@ARGV) || $self->prompt_for_pass($file) || croak "Can't continue without master password";

    my $k = $self->keepass;
    $k->load_db($file, $pass);

    print $k->dump_groups({'group_title !' => 'Backup', 'title !' => 'Meta-Info'});

    my $s = $self->read_config('global_shortcut');
    if (! $s) {
        croak "No global_shortcut defined - hiding away for now";
    }
    $self->grab_global_key($s);
}

sub keepass { shift->{'keepass'} ||= File::KeePass->new }

sub search_auto_type {
    my ($self, $title, $event) = @_;
    print "Looking for match for $title\n";
    foreach my $e ($self->keepass->active_entries) {
        use Data::Dumper;
        print Dumper $e;
#Auto-Type-Window: Chase Online*
#    Auto-Type: {USERNAME}{TAB}{PASSWORD}{ENTER}',
    }
}

1;
