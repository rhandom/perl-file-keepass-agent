package File::KeePass::Agent::unix;

=head1 NAME

File::KeePass::Agent::unix - platform specific utilities for Agent

=cut

use strict;
use warnings;
use Carp qw(croak);
use X11::Protocol;
use vars qw(%keysyms);
use X11::Keysyms qw(%keysyms); # part of X11::Protocol
use IO::Prompt qw(prompt);
#use Term::ReadKey qw(ReadMode GetControlChars);

#my @end;
#END { $_->() for @end };

sub prompt_for_file {
    my $self = shift;
    my $last_file = $self->read_config('last_file');
    if ($last_file && $last_file =~ m{ ^./..(/.+)$ }x) {
        $last_file = $self->home_dir . $1;
    }
    my $file = ''.prompt("Choose the kdb file to open: ", ($last_file ? (-d => $last_file) : ()), -tty);
    if ($last_file
        && $file
        && $last_file ne $file
        && -e $file
        && prompt("Save $file as default kdb database?", -yn, -d => 'y', -tty)) {
        my $home = $self->home_dir;
        my $copy = ($file =~ m{^\Q$home\E(/.+)$ }x) ? "./..$1" : $file;
        $self->write_config(last_file => $copy);
    }

    return $file;
}

sub prompt_for_pass {
    my ($self, $file) = @_;
    return ''.prompt("Enter your master key for $file: ", -e => '*', -tty);
}

sub home_dir {
    my ($user,$passwd,$uid,$gid,$quota,$comment,$gcos,$home,$shell,$expire) = getpwuid($<);
    return $home || croak "Couldn't find home dir for uid $<";
}

sub _config_file {
    my $self = shift;
    my $home = $self->home_dir;
    return "$home/.keepassx/config" if -e "$home/.keepassx/config";
    return "$home/.config/keepassx/config.ini";
}

my %map = (
    last_file => 'LastFile',
    pre_gap   => 'AutoTypePreGap',
    key_delay => 'AutoTypeKeyStrokeDelay',
    );

sub read_config {
    my ($self, $key) = @_;
    my $c = $self->{'config'} ||= $self->_ini_parse($self->_config_file);
    if (! $key) {
        return $c;
    } elsif (my $_key = $map{$key}) {
        return $c->{'Options'}->{$_key};
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
    } else {
        die "Unknown key $key";
    }
}

sub write_config {
    my ($self, $key, $val) = @_;
    my $c = $self->_ini_parse($self->_config_file, 1);
    if (my $_key = $map{$key}) {
        $c->{'Options'}->{$_key} = $val;
    } else {
        return;
    }
    $self->_ini_write($c, $self->_config_file);
    delete $self->{'config'};
}

sub x {
    shift->{'x'} ||= do {
        my $x = X11::Protocol->new;
        $x->{'error_handler'} = sub { my ($x, $d) = @_; die $x->format_error_msg($d) };
        $x;
    };
}

sub grab_global_keys {
    my ($self, @callbacks) = @_;
    #my $ShiftMask                = 1;
    #my $LockMask                 = 2;
    #my $ControlMask              = 4;
    #my $Mod1Mask                 = 8;
    my $Mod2Mask                 = 16;
    #my $Mod3Mask                 = 32;
    #my $Mod4Mask                 = 64;
    #my $Mod5Mask                 = 128;

    my $x = $self->x;
    my %cb_map;
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
        $seq = eval { $x->GrabKey($code, $mod|$Mod2Mask, $x->root, 1, 'Asynchronous', 'Asynchronous') };
        #$seq = eval { $x->GrabKey($code, $mod|$LockMask, $x->root, 1, 'Asynchronous', 'Asynchronous') };
        #$seq = eval { $x->GrabKey($code, $mod|$Mod2Mask|$LockMask, $x->root, 1, 'Asynchronous', 'Asynchronous') };
        $cb_map{$code}->{$mod} = $cb_map{$code}->{$mod|$Mod2Mask} = $callback;
    }

    $x->event_handler('queue');

    #my $in_fh = \*STDIN;
    #local $SIG{'INT'} = sub { ReadMode 'restore', $in_fh; exit };
    #push @end, sub { ReadMode 'restore', $in_fh };
    #ReadMode 'noecho', $in_fh;
    #ReadMode 'raw',    $in_fh;

    #require IO::Select;
    #my $x_fh  = $x->{'connection'}->fh;
    #my $sel   = IO::Select->new($in_fh, $x_fh);

    my $i;
    while (1) {
        #for my $fh ($sel->can_read(0)) {
         #   print "($fh $in_fh $x_fh)\n";
            #if ($fh == $in_fh) {
            #    $self->handle_term_input($fh);
            #} else {
                $self->read_x_event(\%cb_map);
            #}
        #}
    }

#    $x->UngrabKey($code, $mod, $x->root);
}

#sub handle_term_input {
#    my ($self, $fh) = @_;
#
#    my %cntl = GetControlChars $fh;
#    do {
#        my $chr = getc $fh;
#        exit if $chr eq "\e" || $chr eq $cntl{'INTERRUPT'} || $chr eq $cntl{'EOF'};
#        print ">>>$chr\n";
#    } until ! IO::Select->new($fh)->can_read;
#}

sub read_x_event {
    my ($self, $cb_map) = @_;
    my $x = $self->x;
    my %event = $x->next_event;
    return if ($event{'name'} || '') ne 'KeyRelease';
    my $code = $event{'detail'};
    my $mod  = $event{'state'};
    my $callback = $cb_map->{$code}->{$mod} || return;
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
        warn "Could not find window title for window id $orig\n";
        return;
    }
    $event{'_window_id'} = $wid;
    $event{'_window_id_orig'} = $orig;
    $self->$callback($title, \%event);
}

###----------------------------------------------------------------###

sub keymap {
    my $self = shift;
    return $self->{'keymap'} ||= do {
        my $min = $self->x->{'min_keycode'};
        my @map = $self->x->GetKeyboardMapping($min, $self->x->{'max_keycode'} - $min);
        my %map;
        my $req_sh = $self->{'requires_shift'} = {};
        my %rev = reverse %keysyms;
        foreach my $m (@map) {
            my $code = $min++;
            foreach my $pair ([$m->[0], 0], (($m->[1] && $m->[1] != $m->[0]) ? ([$m->[1], 1]) : ())) {
                my ($sym, $shift) = @$pair;
                my $name = $rev{$sym};
                if ($name && ! $map{$name}) {
                    $map{$name} = $code;
                    $req_sh->{$name} = 1 if $shift;
                }
                my $chr = ($sym < 0xFF00) ? chr($sym) : ($sym <= 0xFFFF) ? chr(0xFF & $sym) : next;
                if (defined($name) && $chr ne $name && !$map{$chr}) {
                    $map{$chr} = $code;
                    $req_sh->{$chr} = 1 if $shift;
                }
            }
        }
        $map{"\n"} = $map{"\r"}; # \n mapped to Linefeed - we want it to be Return
        $req_sh->{"\n"} = $req_sh->{"\r"};
        \%map;
    };
}

sub requires_shift {
    my $self = shift;
    $self->keymap;
    return $self->{'requires_shift'};
}

sub keycode {
    my ($self, $key) = @_;
    return $self->keymap->{$key};
}

sub is_key_pressed {
    my $self = shift;
    my $key  = shift || return;
    my $keys = shift || $self->x->QueryKeymap;
    my $code = $self->keycode($key) || return;
    my $byte = substr($keys, $code/8, 1);
    my $n    = ord $byte;
    my $on   = $n & (1 << ($code % 8));
    if ($self->requires_shift->{$key} && @_ <= 3) {
        return if ! $self->is_key_pressed('Shift_L', $keys, 'norecurse');
    }
    return $on;
}

sub are_keys_pressed {
    my $self = shift;
    my $keys = $self->x->QueryKeymap;
    return grep { $self->is_key_pressed($_, $keys) } @_;
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

sub send_key_press {
    my ($self, $auto_type, $entry, $title, $event) = @_;
    warn "Auto-Type: $entry->{'title'}\n" if ref($entry);

    my ($wid) = $self->x->GetInputFocus;

    # wait for all other keys to clear out before we begin to type
    my $i = 0;
    while (my @pressed = $self->are_keys_pressed(qw(Shift_L Shift_R Control_L Control_R Alt_L Alt_R Meta_L Meta_R Super_L Super_R Hyper_L Hyper_R Escape))) {
        print "Waiting for @pressed\n" if 5 == (++$i % 40);
        select(undef,undef,undef,.05)
    }

    my $pre_gap = $self->read_config('pre_gap')   * .001 * 10;
    my $delay   = $self->read_config('key_delay') * .001 * 10;
    my $keymap = $self->keymap;
    my $shift  = $self->requires_shift;
    select undef, undef, undef, $pre_gap if $pre_gap;
    for my $key (split //, $auto_type) {
        my ($_wid) = $self->x->GetInputFocus; # send the key stroke
        if ($_wid != $wid) {
            warn "Window changed.  Aborted Auto-type.\n";
            last;
        }
        my $code  = $keymap->{$key};
        my $state = $shift->{$key} || 0;
        if (! defined $code) {
            warn "Couldn't find code for $key\n";
            next;
        }
        select undef, undef, undef, $delay if $delay;
        $self->key_press($code, $state, $wid);
        $self->key_release($code, $state, $wid);
    }
    return;
}

sub key_press {
    my ($self, $code, $state, $wid) = @_;
    my $x    = $self->x;
    ($wid) = $self->x->GetInputFocus if ! $wid;
    return $x->SendEvent($wid, 0, 0, $x->pack_event(
        name   => "KeyPress",
        detail => $code,
        time   => 0,
        root   => $x->root,
        event  => $wid,
        state  => $state || 0,
        same_screen => 1,
    ));
}

sub key_release {
    my ($self, $code, $state, $wid) = @_;
    my $x    = $self->x;
    ($wid) = $self->x->GetInputFocus if ! $wid;
    return $x->SendEvent($wid, 0, 0, $x->pack_event(
        name   => "KeyRelease",
        detail => $code,
        time   => 0,
        root   => $x->root,
        event  => $wid,
        state  => $state || 0,
        same_screen => 1,
    ));
}

###----------------------------------------------------------------###

sub _ini_parse { # ick - my own config.ini reader - too bad the main cpan entries are overbloat
    my ($self, $file, $order) = @_;
    open my $fh, '<', $file or return {};
    my $block = '';
    my $c = {};
    while (defined(my $line = <$fh>)) {
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        if ($line =~ /^ \[\s* (.*?) \s*\] $/x) {
            $block = $1;
            push @{ $c->{"\eorder\e"} }, $block if $order;
            next;
        } elsif (!length $line || $line =~ /^[;\#]/) {
            push @{ $c->{$block}->{"\eorder\e"} }, \$line if $order;
            next;
        }
        my ($key, $val) = split /\s*=\s*/, $line, 2;
        $c->{$block}->{$key} = $val;
        push @{ $c->{$block}->{"\eorder\e"} }, $key if $order;
    }
    return $c;
}

sub _ini_write {
    my ($self, $c, $file) = @_;
    open my $fh, "+<", $file or die "Could not open file $file for writing: $!";
    for my $block (@{ $c->{"\eorder\e"} || [sort keys %$c] }) {
        print $fh "[$block]\n";
        my $ref = $c->{$block} || {};
        for my $key (@{ $ref->{"\eorder\e"} || [sort keys %$ref] }) {
            if (ref($key) eq 'SCALAR') {
                print $fh $$key,"\n";
            } else {
                print $fh "$key=".(defined($ref->{$key}) ? $ref->{$key} : '')."\n";
            }
        }
    }
    truncate $fh, tell($fh);
    close $fh;
}


=head1 DESCRIPTION

This module provides unix based support for the File::KeePassAgent.  It should
work for anything using an X server.  It should not normally be used on its own.

=head1 FKPA METHODS

The following methods must be provided by an FKPA OS variant.

=over 4

=item C<read_config>

Takes the name of a key to read from the configuration file.  This method reads from
$HOME/.config/keepassx/config.ini.

=item C<prompt_for_file>

Requests the name of a keepass database to open.

=item C<prompt_for_pass>

Requests for the password to open the choosen keepass database.
It is passed the name of the file being opened.

=item C<grab_global_keys>

Takes a list of arrayrefs.  Each arrayref should
contain a shortcut key description hashref and a callback.

    $self->grab_global_keys([{ctrl => 1, shift => 1, alt => 1, key => "c"}, sub { print "Got here" }]);

The callback will be called as a method of the Agent object.  It will
be passed the current active window title and the generating event.

   $self->$callback($window_title, \%event);

This method use X11::Protocol to bind the shortcuts, then listens for the events to happen.

=item C<send_key_press>

Takes an auto-type string, the keepass entry that generated the request,
the current active window title, and the generating event.

This method uses X11::GUITest to "type" the chosen text to the X server.

=back

=head1 OTHER METHODS

These methods are not directly used by the FKPA api.

=over 4

=item C<home_dir>

Used by read_config to find the users home directory.

=item C<x>

Returns an X11::Protocol object

=item C<keymap>

Returns the keymap in use by the X server.

=item C<keysym>

Returns the keysym id used by the X server.

=item C<keycode>

Takes a key - returns the appropriate key code for use in grab_global_keys

=item C<is_key_pressed>

Returns true if the key is currently pressed.  Most useful for items
like Control_L, Shift_L, or Alt_L.

=item C<are_keys_pressed>

Takes an array of key names and returns which ones are currently
pressed.  It has a little bit of caching as part of the process of
calling is_key_pressed.  Returns any of the key names that are pressed.

=item C<attributes>

Takes an X window id - returns all of the attributes for the window.

=item C<property>

Takes an X window id and a property name.  Returns the current value of that property.

=item C<properties>

Takes an X window id - returns all of the properties for the window.

=item C<wm_name>

Takes an X window id - returns its window manager name.

=item C<all_children>

Returns all decended children of an X window.

=back

=head1 AUTHOR

Paul Seamons <paul at seamons dot com>

=head1 LICENSE

This module may be distributed under the same terms as Perl itself.

=cut

1;
