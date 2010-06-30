use ExtUtils::MakeMaker;

###----------------------------------------------------------------###
#  Copyright 2010 - Paul Seamons                                     #
#  Distributed under the GNU General Public License without warranty #
###----------------------------------------------------------------###

WriteMakefile(
              NAME          => "File::KeePass::Agent",
              AUTHOR        => "Paul Seamons",
              ABSTRACT_FROM => "lib/File/KeePass/Agent.pm",
              VERSION_FROM  => "lib/File/KeePass/Agent.pm",
              INSTALLDIRS   => 'site',
              PREREQ_PM     => {
                  'File::KeePass' => '0.1',
                  ((lc($^O) eq 'linux' || lc($^O) eq 'unix') ? (
                       'X11::Protocol' => '0.1',
                       'X11::GUITest'  => '0.1',
                   ) : ()),
              },
              dist          => {
                DIST_DEFAULT => 'all tardist',
                COMPRESS     => 'gzip -vf',
                SUFFIX       => '.gz',
              },
              clean          => {
                FILES        => '*~',
              },
              realclean         => {
                FILES        => '*~',
              },
              );

package MY;

sub postamble {
  return qq^
    
pm_to_blib: README

README: \$(VERSION_FROM)
	pod2text \$(VERSION_FROM) > README
^;
}

1;