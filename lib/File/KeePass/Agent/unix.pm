package File::KeePass::Agent::unix;

=head1 NAME

File::KeePass::Agent::unix - platform specific utilities for Agent

=cut

use strict;
use warnings;
use Carp qw(croak);
use Config::INI::Simple;
use X11::Protocol;
use X11::Keyboard;
use X11::GUITest qw(GetWindowName GetInputFocus);
use IO::Prompt qw(prompt);

sub prompt_for_file {
    my $self = shift;
    my $last_file = $self->read_config('last_file');
    if ($last_file && $last_file =~ m{ ^./..(/.+)$ }x) {
        $last_file = $self->home_dir . $1;
    }
    return ''.prompt("Choose the kdb file to open: ", ($last_file ? (-d => $last_file) : ()));
}

sub prompt_for_pass {
    my ($self, $file) = @_;
    return ''.prompt("Enter your master key for $file: ", -e => '*');
}

sub home_dir {
    my ($user,$passwd,$uid,$gid,$quota,$comment,$gcos,$home,$shell,$expire) = getpwuid($<);
    return $home || croak "Couldn't find home dir for uid $<";
}

sub read_config {
    my ($self, $key) = @_;
    croak "Missing read_config key" if ! $key;

    my $c = $self->{'config'};
    if (! $c) {
        my $home = $self->home_dir;
        my $file = "$home/.config/keepassx/config.ini";
        $c = $self->{'config'} = Config::INI::Simple->new;
        $c->read($file) if -e $file;
    }

    if ($key eq 'last_file') {
        return $c->{'Options'}->{'LastFile'};
    }
    elsif ($key eq 'global_shortcut') {
        return if ! defined(my $key = $c->{'Options'}->{'GlobalShortcutKey'});
        my $mod = $c->{'Options'}->{'GlobalShortcutMods'};
        return if !$mod || $mod !~ m{ ^\@Variant\( \\0\\0\\0\\r\\0\\0\\0\\x5\\x? ([a-f0-9]+) \)$ }x; # non-portable - qvariant \r should be QBitArray, \x5 is 5 bits
        my $val = hex($1);
        my $s = {
            key   => chr($key),
            ctrl  => $val & 0b00001 ? 1 : 0,
            shift => $val & 0b00010 ? 1 : 0,
            alt   => $val & 0b00100 ? 1 : 0,
            altgr => $val & 0b01000 ? 1 : 0,
            win   => $val & 0b10000 ? 1 : 0,
        };
        @{ $s }{qw(ctrl alt)} = (1, 1) if delete $s->{'altgr'};
        return $s;
    }

    return;
}

sub grab_global_keys {
    my ($self, @callbacks) = @_;

    my $x = X11::Protocol->new;
    my $k = X11::Keyboard->new($x);
    my %map;
    foreach my $c (@callbacks) {
        my ($shortcut, $callback) = @$c;

        my $k = X11::Keyboard->new($x);
        my $code = $k->KeysymToKeycode($shortcut->{'key'});
        my $mod  = 0;
        foreach my $row ([ctrl => 'Control'], [shift => 'Shift'], [alt => 'Mod1'], [win => 'Mod4']) {
            next if ! $shortcut->{$row->[0]};
            $mod |= 2 ** $x->num('KeyMask', $row->[1]);
        }
        my $seq = $x->GrabKey($code, $mod, $x->root, 1, 'Asynchronous', 'Asynchronous');
        $map{$seq} = $callback;
    }

    $x->event_handler('queue');
    while (1) {
        my %event = $x->next_event;
        next if ($event{'name'} || '') ne 'KeyRelease';
        my $n = $event{'sequence_number'} || 0;
        my $callback = $map{$n} || next;
        my $active_title = GetWindowName(GetInputFocus());
        $self->$callback($active_title, \%event);
    }

#    $x->UngrabKey($code, $mod, $x->root);
}

1;
