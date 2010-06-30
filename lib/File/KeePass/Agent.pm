#!/usr/bin/perl

=head1 NAME

File::KeePass::Agent - Application agent for working with File::KeePass files

=cut

File::KeePass::Agent::run(),exit if $0 eq __FILE__;

package File::KeePass::Agent;

use strict;
use warnings;
use Carp qw(croak);
use File::KeePass;

our $VERSION = '0.01';
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
        print "Listening on ".$self->shortcut_name($s)." for global shortcut\n";
    }
    foreach my $e ($self->active_entries) {
        next if ! $e->{'comment'} || $e->{'comment'} !~ /^Custom-Global-Shortcut:\s*(.+?)\s*$/m;
        my %info = map {lc($_) => 1} split /[\s+-]+/, $1;
        my %at = $e->{'comment'} =~ m{ ^Auto-Type((?:-\d+)?): \s* (.+?) \s*$ }mxg;
        next if ! scalar keys %at;
        my $at = $at{""} || $at{(sort keys %at)[0]};
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
        $s->{'key'} = lc $keys[0];
        push @callbacks, [$s, sub {
            my ($self, $title, $event) = @_;
            return $self->do_auto_type($at, $e, $title, $event);
        }];
        print "Listening on ".$self->shortcut_name($s)." for entry $e->{'title'}\n";
    }
    if (! @callbacks) {
        croak "No global_shortcut defined - hiding away for now";
    }
    $self->grab_global_keys(@callbacks);
}

sub keepass { shift->{'keepass'} ||= File::KeePass->new }

sub shortcut_name {
    my ($self, $s) = @_;
    my $mod = join("-", map {ucfirst $_} grep {$s->{$_}} qw(ctrl shift alt win));
    return $mod ? "$mod $s->{'key'}" : $s->{'key'};
}

sub active_entries { shift->keepass->find_entries({active => 1, 'group_title !' => 'Backup', 'title !' => 'Meta-Info'}) }

sub active_searches {
    my $self = shift;
    my $s = $self->{'active_searches'} ||= do {
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
                push @s, {'qr' => $t, auto_type => $at, entry => $e};
            }
        }
        \@s;
    };
    return @$s;
}

sub search_auto_type {
    my ($self, $title, $event) = @_;
    my @matches;
    foreach my $row ($self->active_searches) {
        next if $title !~ $row->{'qr'};
        push @matches, $row;
    }
    if (!@matches) {
        $self->do_no_match($title);
    }
    elsif (@matches > 1) {
        $self->do_auto_type_mult(\@matches, $title, $event);
    }
    else {
        $self->do_auto_type($matches[0]->{'auto_type'}, $matches[0]->{'entry'}, $title, $event);
    }
}

sub do_no_match {
    my ($self, $title) = @_;
    warn "No match for \"$title\"\n";
}

sub do_auto_type {
    my ($self, $auto_type, $entry, $title, $event) = @_;

    $auto_type =~ s{ \{ TAB      \} }{\t}xg;
    $auto_type =~ s{ \{ ENTER    \} }{\n}xg;
    $auto_type =~ s{ \{ PASSWORD \} }{
        $self->keepass->locked_entry_password($entry);
    }xeg;
    $auto_type =~ s{ \{ (\w+)    \} }{
        my $key = lc $1;
        defined($entry->{$key}) ? $entry->{$key} : return $self->do_auto_type_unsupported($key);
    }xeg;
    return if ! length $auto_type;
    $self->send_key_press($auto_type, $entry, $title, $event);
}

sub do_auto_type_mult {
    my ($self, $matches, $title, $event) = @_;
    warn "Found multiple matches - using the first\n";
    $self->do_auto_type_mult($matches->[0]->{'auto_type'}, $matches->[0]->{'entry'}, $title, $event);
}

sub do_auto_type_unsupported {
    my ($self, $key) = @_;
    warn "Auto-type key \"$key\" is currently not supported.";
}

1;

__END__

=head1 SYNOPSIS

   use File::KeePass::Agent;
   File::KeePass::Agent::run();

=cut
