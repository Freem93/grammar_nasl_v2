#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-273.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(89016);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/02/29 14:53:56 $");

  script_cve_id("CVE-2014-3693", "CVE-2014-8146", "CVE-2014-8147", "CVE-2014-9093", "CVE-2015-4551", "CVE-2015-45513", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214");

  script_name(english:"openSUSE Security Update : LibreOffice and related libraries (openSUSE-2016-273)");
  script_summary(english:"Check for the openSUSE-2016-273 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for LibreOffice and some library dependencies
(cmis-client, libetonyek, libmwaw, libodfgen, libpagemaker,
libreoffice-share-linker, mdds, libwps) fixes the following issues :

Changes in libreoffice :

  - Provide l10n-pt from pt-PT

  - boo#945047 - LO-L3: LO is duplicating master pages,
    extended fix

  - boo#951579 - LO-L3: [LibreOffice] Calc 5.0 fails to open
    ods files

  - deleted RPATH prevented loading of bundled 3rd party RDF
    handler libs

  - Version update to 5.0.4.2 :

  - Final of the 5.0.4 series

  - boo#945047 - LO-L3: LO is duplicating master pages

  - Version update to 5.0.4.1 :

  - rc1 of 5.0.4 with various regression fixes

  - boo#954345 - LO-L3: Insert-->Image-->Insert as Link
    hangs writer

  - Version update to 5.0.3.2 :

  - Final tag of 5.0.3 release

  - Fix boo#939996 - LO-L3: Some bits from DOCX file are not
    imported

  - Fix boo#889755 - LO-L3: PPTX: chart axis number format
    incorrect

  - boo#679938 - LO-L3: saving to doc file the chapter name
    in the header does not change with chapters

  - Version update to 5.0.3RC1 as it should fix i586 test
    failure

  - Update text2number extension to 1.5.0

  - obsolete libreoffice-mono

  - pentaho-flow-reporting require is conditional on
    system_libs

  - Update icon theme dependencies

  - https://lists.debian.org/debian-openoffice/2015/09/msg00343.html

  - Version bump to 5.0.2 final fate#318856 fate#319071
    boo#943075 boo#945692 :

  - Small tweaks compared to rc1

  - For sake of completion this release also contains
    security fixes for boo#910806 CVE-2014-8147, boo#907636
    CVE-2014-9093, boo#934423 CVE-2015-4551, boo#910805
    CVE-2014-8146, boo#940838 CVE-2015-5214, boo#936190
    CVE-2015-5213, boo#936188 CVE-2015-5212, boo#934423
    CVE-2015-45513, boo#934423 CVE-2015-4551, boo#910805
    CVE-2014-8146, boo#940838 CVE-2015-5214, boo#936190
    CVE-2015-5213, boo#936188 CVE-2015-5212, boo#934423
    CVE-2015-45513, boo#934423 CVE-2015-4551, boo#910805
    CVE-2014-8146, boo#940838 CVE-2015-5214, boo#936190
    CVE-2015-5213, boo#936188 CVE-2015-5212, boo#934423
    CVE-2015-4551

  - Use gcc48 to build on sle11sp4

  - Make debuginfo's smaller on IBS.

  - Fix chrpath call after the libs got -lo suffixing

  - Add patch to fix qt4 features detection :

  - kde4filepicker.patch

  - Split out gtk3 UI to separate subpkg that requires gnome
    subpkg

  - This is to allow people to test gtk3 while it not being
    default

  - Version update to 5.0.2 rc1 :

  - Various small tweaks and integration of our SLE11
    patchsets

  - Update constraints to 30 GB on disk

  - Version bump to 5.0.1 rc2 :

  - breeze icons extension

  - Credits update

  - Various small fixes

  - Version bump to 5.0.1 rc1 :

  - Various small fixes

  - Has some commits around screen rendering -> could fix
    kde bugs

  - Kill branding-openSUSE, stick to TDF branding.

  - Version bump to 5.0 rc5 :

  - Bunch of final touchups here and there

  - Remove some upstreamed patches :

  - old-cairo.patch

  - Add explicit requires over libmysqlclient_r18, should
    cover boo#829430

  - Add patch to build with old cairo (sle11).

  - Version bump to 5.0 rc3 :

  - Various more fixes closing on the 5.0 release

  - Update to 5.0 rc2 :

  - Few small fixes and updates in internal libraries

  - Version bump to 5.0 rc1, remove obsolete patches :

  -
    0001-Fix-could-not-convert-.-const-char-to-const-rtl-OUS
    t.patch

  - 0001-writerperfect-fix-gcc-4.7-build.patch

  - More chrpat love for sle11

  - Add python-importlib to build/requirements on py2
    distros

  - Provide/obsolete crystal icons so they are purged and
    not left over

  - Fix breeze icons handling, drop crystal icons.

  - Version bump to 5.0.0.beta3 :

  - Drop merged patch
    0001-Make-cpp-poppler-version.h-header-optional.patch

  - Update some internal tarballs so we keep building

  - based on these bumps update the buildrequires too

  - Generate python cache files wrt boo#929793

  - Update %post scriptlets to work on sle11 again

  - Split out the share -> lib linker to hopefully allow
    sle11 build

  - One more fix for help handling boo#915996

  - Version bump to 4.4.3 release :

  - Various small fixes all around

  - Disable verbose build to pass check on maximal size of
    log

  - We need pre/post for libreoffice in langpkgs

  - Use old java for detection and old commons-lang/codec to
    pass brp check on java from sle11

  - 0001-Make-HAVE_JAVA6-be-always-false.patch

  - Revert last changeset, it is caused by something else
    this time :

  - 0001-Set-source-and-target-params-for-java.patch

  - Set source/target for javac when building to work on
    SLE11 :

  - 0001-Set-source-and-target-params-for-java.patch

  - Try to deal with rpath on bundled libs

  - Fix python3_sitelib not being around for py2

  - Add internal make for too old system

  - One more stab on poppler switch :

  - 0001-Make-cpp-poppler-version.h-header-optional.patch

  - Update the old-poppler patch to work correctly :

  - 0001-Make-cpp-poppler-version.h-header-optional.patch

  - Sort out more external tarballs for the no-system-libs
    approach

  - Add basic external tarballs needed for
    without-system-libraries

  - Add patch to check for poppler more nicely to work on
    older distros :

  - 0001-Make-cpp-poppler-version.h-header-optional.patch

  - Try to pass configure without system libs

  - Allow switch between py2 and py3

  - Move external dependencies in conditional thus allow
    build on SLE11

  - Add conditional for noarch subpackages

  - Add switch in configure to detect more of
    internal/external stuff

  - Add conditional for appdatastore thing and redo it to
    impact the spec less

  - Add systemlibs switch to be used in attempt to build
    sle11 build

  - Silence more scarry messages by boo#900186

  - Fixes autocorr symlinking

  - Cleans UNO cache in more pretty way

  - Clean up the uno cache removal to not display scarry
    message boo#900186

  - Remove patch to look for help in /usr/share, we symlink
    it back to lib, so there is no actual need to search for
    it directly, migth fix boo#915996 :

  - officecfg-help-in-usr-share.diff

  - --disable-collada

  - reportedly it does not work in LibreOffice 4.4

  - added version numbers to some BuildRequires lines

  - Require flow engine too on base

  - Fix build on SLE12 and 13.1 by adding conditional for
    appdata install

  - Fixup the installed appdata.xml files: they reference a
    .desktop file that are not installed by libreoffice
    (boo#926375).

  - Version bump to 4.4.2 :

  - 2nd bugfix update for the 4.4 series

  - BuildRequires: libodfgen-devel >= 0.1

  - added version numbers to some BuildRequires lines

  - build does not require python3-lxml

  - build requires librevenge-devel >= 0.0.1

  - vlc media backend is broken, don't use it. Only
    gstreamer should be used.

  - Install the .appdata.xml files shipped by upstream:
    allow LO to be shown in AppStream based software
    centers.

  - Move pretrans to pre

  - Version bump to 4.4.1 first bugfix release of the series

  - Reduce bit the compilation preparations as we prepped
    most of the things by _constraints and it is no longer
    needed

  - %pre is not enough the script needs to be rewritten in
    lua

  - Move removal of obsolete dirs from %pretrans to %pre
    boo#916181

  - Version bump to 4.4.0 final :

  - First in the 4.4 series

  - First release to have the new UI elements without old
    hardcoded sizes

  - Various improvements all around.

  - Version bump to 4.4.0rc2 :

  - Various bugfixes, just bumping to see if we still build
    fine.

  - That verbose switch for configure was really really bad
    idea

  - generic images.zip for galaxy icons seem gone so remove

  - Do not supplement kde3 stuff, it is way beyond obsolete

  - Remove vlc conditional

  - korea.xcd is no more so remove

  - Really use mergelib

  - Disable telepathy, it really is experimental like hell

  - Version bump to 4.4.0rc1 :

  - New 4.4 branch release with additional features

  - Enable collada :

  - New bundled collada2gltf tarball:
    4b87018f7fff1d054939d19920b751a0-collada2gltf-master-cb1
    d97788a.tar.bz2

  - Remove errorous self-obsolete in lang pkgs.

  - Version bump to 4.3.3.2 :

  - Various bugfixes from maintenance branch to copy
    openSUSE.

  - Also contains fix for boo#900214 and boo#900218
    CVE-2014-3693

  - fix regression in bullets (boo#897903).

  - Add masterpage_style_parent.odp as new file for
    regression test for bullets. Changes in cmis-client :

  - Update to version 0.5.0

  + Completely removed the dependency on InMemory server for
    unit tests

  + Minimized the number of HTTP requests sent by
    SessionFactory::createSession

  + Added Session::getBaseTypes()

  - Bump soname to 0_5-5

  - Bump incname to 0.5

Changes in libetonyek :

  - Version bump to 0.1.3 :

  - Various small fixes

  - More imported now imported

  - Now use mdds to help with some hashing

  - Version bump to 0.1.2 :

  - Initial support for pages and numbers

  - Ditch libetonyek-0.1.1-constants.patch as we do not
    require us to build for older boost

Changes in libmwaw :

  - Version bump to 0.3.6 :

  - Added a minimal parser for ApplePict v1.v2, ie. no
    clipping, does not take in account the copy mode:
    srcCopy, srcOr, ...

  - Extended the --with-docs configure option to allow to
    build doc only for the API classes:
    --with-docs=no|api|full .

  - Added a parser for MacDraft v4-v5 documents.

  - RagTime v5-v6 parser: try to retrieve the main layouts
    and the picture/shape/textbox, ie. now, it generates
    result but it is still very imcomplete... 

  - MWAW{Graphic,Presentation,Text}Listener: corrected a
    problem in openGroup which may create to incorrect
    document.

  - Created an MWAWEmbeddedObject class to store a picture
    with various representations.

  - MWAW*Listener: renamed insertPicture to insertShape,
    added a function to insert a texbox in a
    MWAWGraphicShape (which only insert a basic textbox).

  - Fixed many crashes and hangs when importing broken
    files, found with the help of american-fuzzy-lop.

  - And several other minor fixes and improvements.

  - Version bump to 0.3.5

  - Various small fixes on 0.3 series, nothing big woth
    mention

Changes in libodfgen :

  - Version bump to 0.1.4 :

  - drawing interface: do no forget to call
    startDocument/endDocument when writing in the manifest

  - metadata: added handler for 'template' metadata, unknown
    metadata are written in a meta:user-defined elements,

  - defineSheetNumberingStyle: can now define styles for the
    whole document (and not only for the actual sheet)

  - update doxygen configuration file + add a make astyle
    command

  - Allow writing meta:creation-date metadata element for
    drawings and presentations too.

  - Improve handling of headings. Most importantly, write
    valid ODF.

  - Write meta:generator metadata element.

  - Add initial support for embedded fonts. It is currently
    limited to Flat ODF output.

  - Upgrade to version 0.1.2

  - Use text:h element for headings. Any paragraph with
    text:outline-level property is recognized as a heading.

  - Handle layers.

  - Improve handling of styles. Particularly, do not emit
    duplicate styles.

  - Slightly improve documentation.

  - Handle master pages.

  - Do not expect that integer properties are always in
    inches.

  - Fix misspelled style:paragraph-properties element in
    presentation notes.

  - Only export public symbols on Linux.

  - Fix bogus XML-escaping of metadata values.

  - And many other improvements and fixes.

Changes in libpagemaker :

  - Initial package based on upstream libpagemaker 0.0.2

Changes in libreoffice-share-linker :

  - Initial commit, split out from main libreoffice package
    to workaround issues on SLE11 build Changes in mdds :

  - Update to version 0.12.1 :

  - Various small fixes on 0.12 series

  - Just move define up and comment why we redefine docdir

  - more types are possible in segment_tree data structures
    (previously only pointers were possible)

  - added sorted_string_map

  - multi_type_vector bugfixes Changes in libwps :

  - Update to version 0.4.1 :

  + QuattroPro: correct a mistake when reading negative
    cell's position.

  + Fix some Windows build problems.

  + Fix more than 10 hangs when reading damaged files, found
    with the help of american-fuzzy-lop.

  + Performance: improve the sheet's output generation.

  + add support for unknown encoding files (ie. DOS file)

  + add potential support for converting Lotus, ...
    documents,

  + accept to convert all Lotus Wk1 files and Symphony Wk1
    files,

  + add support for Lotus Wk3 and Wk4 documents,

  + add support for Quattro Pro Wq1 and Wq2 documents,

  + only in debug mode, add pre-support for Lotus Wk5...,
    must allow to retrieve the main sheets content's with no
    formatting,

  + add potential support for asking the document's password
    ( but do nothing )

  + correct some compiler warnings when compiling in debug
    mode.

  + Fix parsing of floating-point numbers in specific cases.

  + Fix several minor issues reported by Coverity and Clang.

  + Check arguments of public functions. Passing NULL no
    longer causes a crash.

  + Use symbol visibility on Linux. The library only exports
    the public functions now.

  + Import @TERM and @CTERM functions (fdo#86241).

  + Handle LICS character encoding in spreadsheets
    (fdo#87222).

  + Fix a crash when reading a broken file, found with the
    help of american-fuzzy-lop."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=679938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=829430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=889755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=940838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-openoffice/2015/09/msg00343.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected LibreOffice and related libraries packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cmis-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cmis-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cmis-client-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-0_5-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-0_5-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-c-0_5-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-c-0_5-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-0_1-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-0_3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-0_3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmwaw-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libodfgen-0_1-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libodfgen-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libodfgen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libodfgen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpagemaker-0_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpagemaker-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpagemaker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpagemaker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpagemaker-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpagemaker-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-sifr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-share-linker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-0_4-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-0_4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mdds-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"cmis-client-0.5.0-4.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cmis-client-debuginfo-0.5.0-4.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cmis-client-debugsource-0.5.0-4.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcmis-0_5-5-0.5.0-4.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcmis-0_5-5-debuginfo-0.5.0-4.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcmis-c-0_5-5-0.5.0-4.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcmis-c-0_5-5-debuginfo-0.5.0-4.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcmis-c-devel-0.5.0-4.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcmis-devel-0.5.0-4.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libetonyek-0_1-1-0.1.3-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libetonyek-0_1-1-debuginfo-0.1.3-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libetonyek-debugsource-0.1.3-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libetonyek-devel-0.1.3-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libetonyek-tools-0.1.3-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libetonyek-tools-debuginfo-0.1.3-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmwaw-0_3-3-0.3.6-2.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmwaw-0_3-3-debuginfo-0.3.6-2.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmwaw-debugsource-0.3.6-2.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmwaw-devel-0.3.6-2.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmwaw-tools-0.3.6-2.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmwaw-tools-debuginfo-0.3.6-2.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libodfgen-0_1-1-0.1.4-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libodfgen-0_1-1-debuginfo-0.1.4-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libodfgen-debugsource-0.1.4-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libodfgen-devel-0.1.4-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpagemaker-0_0-0-0.0.2-2.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpagemaker-0_0-0-debuginfo-0.0.2-2.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpagemaker-debugsource-0.0.2-2.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpagemaker-devel-0.0.2-2.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpagemaker-tools-0.0.2-2.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpagemaker-tools-debuginfo-0.0.2-2.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-drivers-mysql-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-drivers-mysql-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-drivers-postgresql-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-drivers-postgresql-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-branding-upstream-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-calc-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-calc-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-calc-extensions-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-debugsource-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-draw-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-draw-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-filters-optional-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-gnome-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-gnome-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-gtk3-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-gtk3-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-breeze-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-galaxy-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-hicontrast-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-oxygen-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-sifr-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-tango-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-impress-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-impress-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-kde4-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-kde4-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-af-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ar-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-as-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-bg-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-bn-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-br-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ca-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-cs-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-cy-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-da-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-de-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-dz-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-el-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-en-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-es-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-et-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-eu-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-fa-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-fi-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-fr-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ga-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-gl-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-gu-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-he-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-hi-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-hr-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-hu-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-it-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ja-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-kk-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-kn-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ko-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-lt-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-lv-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-mai-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ml-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-mr-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-nb-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-nl-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-nn-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-nr-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-nso-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-or-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-pa-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-pl-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-pt-BR-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-pt-PT-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ro-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ru-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-si-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-sk-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-sl-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-sr-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ss-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-st-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-sv-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ta-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-te-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-th-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-tn-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-tr-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ts-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-uk-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ve-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-xh-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-zh-Hans-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-zh-Hant-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-zu-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-mailmerge-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-math-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-math-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-officebean-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-officebean-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-pyuno-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-pyuno-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-sdk-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-sdk-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-share-linker-1-2.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-writer-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-writer-debuginfo-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-writer-extensions-5.0.4.2-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwps-0_4-4-0.4.1-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwps-0_4-4-debuginfo-0.4.1-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwps-debugsource-0.4.1-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwps-devel-0.4.1-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwps-tools-0.4.1-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwps-tools-debuginfo-0.4.1-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mdds-devel-0.12.1-2.4.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cmis-client / cmis-client-debuginfo / cmis-client-debugsource / etc");
}
