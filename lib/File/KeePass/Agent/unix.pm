package File::KeePass::Agent::unix;

=head1 NAME

File::KeePass::Agent::unix - platform specific utilities for Agent

=cut

use strict;
use warnings;
use Carp qw(croak);
use Config::INI::Simple;
use X11::GUITest qw(PressKey ReleaseKey PressReleaseKey SendKeys QuoteStringForSendKeys);
use X11::Protocol;
use vars qw(%keysyms);
use X11::Keysyms qw(%keysyms); # part of X11::Protocol
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

sub x {
    shift->{'x'} ||= do {
        my $x = X11::Protocol->new;
        $x->{'error_handler'} = sub { my ($x, $d) = @_; use CGI::Ex::Dump qw(debug); debug $d, CGI::Ex::Dump::ctrace(); die $x->format_error_msg($d) };
        $x;
    };
}

sub grab_global_keys {
    my ($self, @callbacks) = @_;
    my $x = $self->x;

    my %map;
    foreach my $c (@callbacks) {
        my ($shortcut, $callback) = @$c;

        my $code = $self->keycode($shortcut->{'key'});
        my $mod  = 0;
        foreach my $row ([ctrl => 'Control'], [shift => 'Shift'], [alt => 'Mod1'], [win => 'Mod4']) {
            next if ! $shortcut->{$row->[0]};
            $mod |= 2 ** $x->num('KeyMask', $row->[1]);
        }
        my $seq = eval { $x->GrabKey($code, $mod, $x->root, 1, 'Asynchronous', 'Asynchronous') };
        croak "The key binding ".$self->shortcut_name($shortcut)." is already in use" if ! $seq;
        $map{$code}->{$mod} = $callback;
    }

    $x->event_handler('queue');
    my $i;
    while (1) {
        my %event = $x->next_event;
        next if ($event{'name'} || '') ne 'KeyRelease';
        my $code = $event{'detail'};
        my $mod  = $event{'state'};
        my $callback = $map{$code}->{$mod} || next;

        my ($wid) = $x->GetInputFocus;
        my $orig  = $wid;
        my $title = eval { $self->wm_name($wid) };
        while (!defined($title) || ! length($title)) {
            last if $wid == $x->root;
            my ($root, $parent) = $x->QueryTree($wid);
            last if $parent == $wid;
            $wid = $parent;
            $title = eval { $self->wm_name($wid) };
        }
        if (!defined($title) || !length($title)) {
            warn "Couldn't find window title for window id $orig\n";
            next;
        }
        $event{'_window_id'} = $wid;
        $event{'_window_id_orig'} = $orig;
        $self->$callback($title, \%event);

    }

#    $x->UngrabKey($code, $mod, $x->root);
}

###----------------------------------------------------------------###

sub keymap {
    my $self = shift;
    return $self->{'keymap'} ||= do {
        my $min = $self->x->{'min_keycode'};
        my @map = $self->x->GetKeyboardMapping($min, $self->x->{'max_keycode'} - $min);
        croak "Couldn't find the keyboard map" if ! @map;
        my $m = {map { $map[$_][0] => $_ + $min } 0 .. $#map}; # return of the do
    };
}

sub keycode {
    my ($self, $key) = @_;
    $key = $keysyms{$key} if $key !~ /^\d+$/;
    return $self->keymap->{$key};
}

###----------------------------------------------------------------###

sub attributes {
    my ($self, $wid) = @_;
    return {$self->x->GetWindowAttributes($wid)};
}

sub property {
    my ($self, $wid, $prop) = @_;
    return '' if !defined($wid) || $wid =~ /\D/;
    $prop = $self->x->atom($prop) if $prop !~ /^\d+$/;
    my ($val) = $self->x->GetProperty($wid, $prop, 'AnyPropertyType', 0, 255, 0);
    return $val;
}

sub properties {
    my ($self, $wid) = @_;
    my $x = $self->x;
    return {map {$x->atom_name($_) => $self->property($wid, $_)} $x->ListProperties($wid) };
}

sub wm_name {
    my ($self, $wid) = @_;
    return $self->property($wid, 'WM_NAME');
}

sub all_children {
    my ($self, $wid, $cache, $level) = @_;
    $cache ||= {};
    $level ||= 0;
    next if exists $cache->{$wid};
    $cache->{$wid} = $level;
    my ($root, $parent, @children) = $self->x->QueryTree($wid);
    $self->all_children($_, $cache, $level + 1) for @children;
    return $cache;
}

###----------------------------------------------------------------###

sub load_xtest {
    my $self = shift;
    my $x = $self->x;
    return if $x->{'ext'}->{'XTEST'};
    return if $x->{'ext'}->{'XTEST_FKP'};
    $x->init_extension('XTEST'); # future proof - let X11::Protocol eventually add the extension
    return if $x->{'ext'}->{'XTEST'};
    if (! grep {$_ eq 'XTEST'} $x->ListExtensions) {
        die "Cannot access the XTEST extension for sending key input - extension doesn't exist.\n";
    }

    # hack together a micro extension
    my ($major, $event, $error) = $self->x('QueryExtension', 'XTEST');
    my $ref = $x->{'ext_request'}->{$major} = [
        ["XTestFakeKeyEvent", sub {
            my $self = shift;
            my ($key, $state, $send_delay) = @_;
            return pack("CSL", $key, $state ? 1 : 0, $send_delay || 100);
        }]];
    $x->{'ext_request_num'}->{$ref->[$_]->[0]} = [$major, $_] for 0 .. $#$ref;
    $x->{'ext'}->{'XTEST_FKP'} = [$major, $event, $error, undef];
    use CGI::Ex::Dump qw(debug);
}

sub send_key_press {
    my ($self, $auto_type, $entry, $title, $event) = @_;
    warn "Auto-Type: $entry->{'title'}\n";

    select(undef,undef,undef,.5);
    my $s = QuoteStringForSendKeys($auto_type);
    SendKeys($s);

    return;

    $self->load_xtest;
    my $key = $self->keycode('w');
    my $x = $self->x;
use CGI::Ex::Dump qw(debug);
debug  'one';
#    $x->XTestFakeKeyEvent($key, $x->num('Bool', 'True'), 0);
#    $x->XTestFakeKeyEvent($key, $x->num('Bool', 'False'), 0);
#    $x->flush;
    debug 'three';
#    retval = (BOOL)XTestFakeKeyEvent(TheXDisplay, kc, True, EventSendDelay);
#    retval = (BOOL)XTestFakeKeyEvent(TheXDisplay, kc, False, EventSendDelay);
#    XFlush(TheXDisplay);
#    return(retval);

}

1;
