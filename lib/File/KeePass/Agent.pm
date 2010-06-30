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

    my @callbacks;
    if (my $s = $self->read_config('global_shortcut')) {
        push @callbacks, [$s, 'search_auto_type'];
    }
    foreach my $e ($self->active_entries) {
        next if ! $e->{'comment'} || $e->{'comment'} !~ /^Custom-Global-Shortcut:\s*(.+?)\s*$/m;
        my %info = map {lc($_) => 1} split /[\s+-]+/, $1;
        my $s = {
            ctrl  => delete($info{'control'}) || delete($info{'cntrl'}) || delete($info{'ctrl'}),
            shift => delete($info{'shift'}) || delete($info{'shft'}),
            alt   => delete($info{'alt'}),
            win   => delete($info{'win'}),
        };
        my @keys = keys %info;
        if (@keys != 1) {
            croak "Cannot set global shortcut with more than one key (@keys) for entry \"$e->{'title'}\"\n";
        }
        $s->{'key'} = $keys[0];
        push @callbacks, [$s, sub {
            my ($self, $title, $event) = @_;
            return $self->do_auto_type($e, $title, $event);
        }];
    }
    if (! @callbacks) {
        croak "No global_shortcut defined - hiding away for now";
    }
    $self->grab_global_keys(@callbacks);
}

sub keepass { shift->{'keepass'} ||= File::KeePass->new }

sub active_entries { shift->keepass->find_entries({active => 1, 'group_title !' => 'Backup', 'title !' => 'Meta-Info'}) }

sub active_searches {
    my $self = shift;
    return $self->{'active_searches'} ||= do {
        my @s;
        foreach my $e ($self->active_entries) {
            next if ! $e->{'comment'};
            my %at = $e->{'comment'} =~ m{ ^Auto-Type((?:-\d+)?): \s* (.+?) \s*$ }mxg;
            next if ! scalar keys %at;
            my @w  = $e->{'comment'} =~ m{ ^Auto-Type-Window((?:-\d+)?): \s* (.+?) \s*$ }mxg;
            while (@w) {
                my $n = shift @w;
                my $t = shift @w;
                my $at = defined($at{$n}) ? $at{$n}: defined($at{""}) ? $at{""} : next;
                $t = quotemeta($t);
                $t =~ s{^\\\*}{.*};
                $t =~ s{\\\*$}{.*};
                $t = qr{^$t$};
                push @s, [$t, $at, $e];
            }
        }
        \@s;
    };
}

sub search_auto_type {
    my ($self, $title, $event) = @_;
    print "Looking for match for $title\n";
    my @matches;
    foreach my $row ($self->active_searches) {
        next if $title !~ $row->[0];
        push @matches, $row;
    }
    use CGI::Ex::Dump qw(debug);
debug \@matches;

}

sub do_auto_type {
    my ($self, $entry, $title, $event) = @_;
    use CGI::Ex::Dump qw(debug);
    debug $entry, $title, $event;
}

1;
