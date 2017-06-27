#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(52735);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:52:01 $");

  script_cve_id("CVE-2010-2935", "CVE-2010-2936", "CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-3702", "CVE-2010-3704", "CVE-2010-4253", "CVE-2010-4643");

  script_name(english:"SuSE 11.1 Security Update : Libreoffice (SAT Patch Number 4082)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Maintenance update to LibreOffice-3.3.1. It adds some interesting
features, fixes many bugs, including several security vulnerabilities.

The previous OpenOffice_org packages are also renamed to libreoffice.

LibreOffice is continuation of the OpenOffice.org project. This update
replaces the OpenOffice.org installation, including helper packages,
e.g. dictionaries, templates. The new stuff is backward compatible.

List of LibreOffice-3.3 features :

General

  - online help

  - common search toolbar

  - new easier 'Print' dialog

  - new easier 'Thesaurus' dialog

  - more options to modify letters case

  - added LibreOffice colors to the palette

  - import of alpha channel for RGBA TIFF (fdo#30472) Calc

  - sort dialog for DataPilot

  - increased document protection

  - insert drawing objects in charts

  - hierarchical axis labels for charts

  - automatic decimals digits for 'General' format

  - new tab page 'Compatibility' in the Options dialog

  - better performance and interoperability on Excel import

  - display custom names for DataPilot fields, items, and
    totals Writer

  - RTF export (GSoc)

  - new 'Title Page' dialog

  - 2-level document protection

  - better form controls handling

  - count the number of characters with and without spaces
    Impress/Draw

  - PPTX chart import feature

  - easier slide layout handling

  - presenter screen uses the laptop output by default

  - allow to add drawing documents to gallery via API
    (i#80184) Base

  - support explicit primary key

  - support of read-Only database registrations Math

  - new command 'nospace' Most important changes :

  - maintenance update (bnc#667421,
    MaintenanceTracker-38738)

  - fixed several security bugs :

  - PowerPoint document processing. (CVE-2010-2935 /
    CVE-2010-2936)

  - extensions and filter package files. (CVE-2010-3450)

  - RTF document processing. (CVE-2010-3451 / CVE-2010-3452)

  - Word document processing. (CVE-2010-3453 /
    CVE-2010-3454)

  - insecure LD_LIBRARY_PATH usage. (CVE-2010-3689)

  - PDF Import extension resulting from 3rd party library
    XPD. (CVE-2010-3702 / CVE-2010-3704)

  - PNG file processing. (CVE-2010-4253)

  - TGA file processing. (CVE-2010-4643)

  - libreoffice-3.3.1.2 == 3.3.1-rc2 == final

  - fixed audio/video playback in presentation (deb#612940,
    bnc#651250)

  - fixed non-working input methods in KDE4. (bnc#665112)

  - fixed occasional blank first slide (fdo#34533)

  - fixed cairo canvas edge count calculation. (bnc#647959)

  - defuzzed piece-packimages.diff to apply

  - updated to libreoffice-3.3.1.2 (3.3.1-rc2) :

  - l10n

  - updated some translations

  - libs-core

  - crashing oosplash and malformed picture. (bnc#652562)

  - Byref and declare Basic statement (fdo#33964, i#115716)

  - fixed BorderLine(2) conversion to SvxBorderLine
    (fdo#34226)

  - libs-gui

  - getEnglishSearchFontName() searches Takao fonts

  - sdk

  - fix ODK settings.mk to only set STLPORTLIB if needed

  - writer

  - rtfExport::HackIsWW8OrHigher(): return true (fdo#33478)

  - visual editor destroys formulas containing symbols
    (fdo#32759, fdo#32755)

  - enabled KDE4 support for SLED11; LO-3.3.1 fixed the
    remaining annoying bugs

  - fixed EMF+ import. (bnc#650049)

  - updated to libreoffice-3.3.1.1 (3.3.1-rc1) :

  - artwork

  - new MIME type icons for LibreOffice

  - bootstrap

  - wrong line break with ( (fdo#31271)

  - build

  - default formula string (n#664516)

  - don't version the bundled ct2n extension

  - last update of translations from Pootle for 3.3.1

  - calc

  - import of cell attributes from Excel documents

  - incorrect page number in page preview mode (fdo#33155)

  - components

  - remove pesky on-line registration menu entry (fdo#33112)

  - crash on changing position of drawing object in header
    (rhbz#673819)

  - extras

  - start using technical.dic instead of oracle.dic
    (fdo#31798)

  - filters

  - pictures DOCX import. (bnc#655763)

  - parse 'color' property (fdo#33551)

  - fix ole object import for writer (DOCX) (fdo#33237)

  - help

  - OOo -> LibO on Getting Support page (fdo#33249)

  - libs-core

  - handle css::table::BorderLine

  - add preferred Malayalam fonts (fdo#32953)

  - fix KDE3 library search order (fdo#32797)

  - StarDesktop.terminate macro behaviour (#30879)

  - Sun Microsystems -> TDF in desktop file (fdo#31191)

  - fixed several crashes around config UNO API (fdo#33994)

  - implementation names weren't matching with xcu
    (fdo#32872)

  - improve the check for existence of the localized help
    (fdo#33258)

  - libs-extern

  - upgrade libwpd to 0.9.1

  - libs-gui

  - painting of axial gradients (116318)

  - fix wrong collation for Catalan language

  - crash when moving through database types (fdo#32561)

  - paint toolbar handle positioned properly (fdo#32558)

  - remove the menu when Left Alt Key was pressed; for GTK

  - default currency for Estonia should be Euro (fdo#33160)

  - year of era in long format for zh_TW by default
    (fdo#33459)

  - writer

  - use standard Edit button width of 50 (fdo#32633)

  - improve formfield checkbox binary export. (bnc#660816)

  - infinite loop while exporting some files in DOC/DOCX/RTF

  - CTL/Other Default Font (i#25247, i#25561, i#48064,
    i#92341)

  - libreoffice-build-3.3.0.4 == 3.3.0-rc4 == final

  - updated to libreoffice-3.3.0.4 (3.3-rc4) :

  - common :

  - remove pesky on-line registration menu entry (fdo#33112)

  - artwork :

  - fix search toolbar up/down search button icons

  - base :

  - report builder not shows properties on report fields
    (fdo#32742)

  - report left/right page margin setting ignored on 64-bit
    (i#116187)

  - build :

  - updated translations

  - calc :

  - reverted problematic and dangerous: # performance of
    filters with many filtered ranges (i#116164) # obtain
    correct data range for external references (i#115906)

  - libs-core :

  - FMR crasher (fdo#33099)

  - backgrounds for polypolygons in metafile (i#116371)

  - unopkg crasher on SLED11-SP1. (bnc#655912)

  - libs-gui :

  - use sane scrollbar sizes when drawing

  - painting of axial gradients (i#116318)

  - do not mix unrelated X11 Visuals (fdo#33108)

  - avoid GetHelpText() call which can be quite heavy

  - writer :

  - fields fixes: key inputs, 0-length fields import.
    (bnc#657135)

  - replaced obsolete SuSEconfig gtk2 module call with
    %%icon_theme_cache_post(un) macros for openSUSE > 11.3.
    (bnc#663245)

  - updated to libreoffice-3.3.0.3 (3.3-rc3) :

  - build :

  - use libreoffice and lo* wrappers; update man pages
    accordingly

  - navigation buttons' patch selection handling (fdo#32380,
    bnc#649506)

  - calc :

  - bogus check for numerical sheet names (fdo#32570)

  - performance of filters with many filtered ranges
    (i#116164)

  - obtain correct data range for external references
    (i#115906)

  - avoid double-paste when pasting text into cell comment
    (fdo#32572)

  - components :

  - fix nsplugin for LibreOffice name

  - fixing large OOXML files (i#115944)

  - layout breakage for KDE, X11 and (possibly) Mac
    (fdo#32133)

  - extensions :

  - patching xpdf to patchlevel 3.02pl5

  - extras :

  - creating technical.dic based on src/*.dic

  - filters :

  - small TGAReader improvement (i#164349)

  - PageRange handling in writer PDF export (#116085)

  - impress :

  - missing font color (rhbz#663857)

  - use updated anchor for group shapes (i#115898)

  - presentation objects on master pages (i#115993)

  - libs-core :

  - survive missing window (rhbz#666216)

  - better font selection in Japanese locale.

  - do not block when launching Firefox (fdo#32427)

  - show the license information in a separate dialog
    (fdo#32563)

  - make unopkg --suppress-license skip license in all cases
    (fdo#32840)

  - libs-extern-sys :

  - better XPATH handling (i#164350)

  - libs-gui :

  - use the initial language if not specified (fdo#32523)

  - clean up search cache singleton in correct order
    (rhbz#666088)

  - writer :

  - undo/redo crash with postits (rhbz#660342)

  - rearrange title dialog to get translations (fdo#32633)

  - move to the next record during mail merge (fdo#32790)

  - updated to libreoffice-3.3.0.2 (3.3-rc2) :

  - common :

  - copy &amp; paste a text formatted cell (i#115825)

  - replaced http://www.openoffice.org (fdo#32169)

  - bootstrap :

  - check if KDE is >= 4.2

  - cleanup unfortunate license duplication

  - calc :

  - ignore preceding spaces when parsing numbers

  - make the string 'New Record' localizable (fdo#32209)

  - remove trailing spaces too when parsing CSV simple
    numbers

  - display correct record information in Data Form dialog
    (fdo#32196)

  - components :

  - make the ODMA check box clickable again (fdo#32132)

  - fixed the sizes of Tips and Extended tips check boxes

  - make 'Reset help agent' button clickable again
    (fdo#32132)

  - extensions :

  - fix filled polygons on PDF import

  - filters :

  - performance for import of XLSX files with drawing
    objects (i#115940)

  - impress :

  - missing embedded object in ODP export (i#115898)

  - grey as default color for native tables in Impress

  - graphics on master page cannot be deleted (i#115993)

  - libs-core :

  - save with the proper DOC variant (fdo#32219)

  - removed dupe para ids introduced by copy&amp;paste

  - colon needed for LD_LIBRARY_PATH set but empty

  - wikihelp: use the right Help ID URL (fdo#32338)

  - MySQL Cast(col1 as CHAR) yields error (i#115436)

  - import compatibility for enhanced fields names
    (fdo#32172)

  - libs-extern-sys :

  - XPATH handling fix

  - libs-gui :

  - PPTX import crasher. (bnc#654065)

  - copy&amp;paste problem of metafiles (i#115825)

  - force Qt paint system to native (fdo#30991)

  - display problem with Vegur font (fdo#31243)

  - URIs must be exported as 7bit ASCII (i#115788)

  - regression in WMF text rendering (fdo#32236, i#115825)

  - postprocess :

  - only register EvolutionLocal when EVO support is enabled
    (fdo#32007)

  - writer :

  - after 'data to fields' mail merge does not work
    (fdo#31190)

  - missing outline feature in new RTF export filter
    (fdo#32039)

  - encoding of Greek letters names with accent in French
    (i#115956)

  - build bits :

  - better build identification in the about dialog

  - updated to libreoffice-3.3.0.1 (3.3-rc1) :

  - ooo integration :

  - Merge commit 'ooo/OOO330_m17' into libreoffice-3-3

  - common :

  - more RTF import/export fixes

  - updated branding for rc

  - artwork :

  - fixed icons with PNG optimizations

  - remove remaining ODF MIME type icons

  - bootstrap :

  - Add BrOffice artwork / branding support

  - Do not install HTML versions of LICENSE and README

  - install credits file

  - build :

  - empty toolbar. (bnc#654039)

  - pack PostgreSQL driver as .oxt instead of .zip

  - calc :

  - avoid pasting data from OOo Calc as an OLE object

  - scaling factor calculation for drawing layer (i#115313)

  - broken filter option in Datapilot (i#115431)

  - 'Precision as shown' not working if automatic decimal
    (i#115512)

  - disable document modify and broadcasting of changes on
    range names

  - don't update visible ranges for invisible panes

  - changing margins in print preview should mark the
    document modified

  - make VLOOKUP work with an external reference once again
    (fdo#31718)

  - more strict parsing of external range names

  - no automatic width adjustment of the dropdown popups
    (fdo#31710)

  - re-calculate visible range when switching sheets

  - skip hidden cells while expanding range selection

  - components :

  - overlapping controls

  - bad alloc and convert to ZipIOException (rh#656191)

  - divide by zero (rh#657628)

  - extras :

  - use consistent autocorrect file names

  - filters :

  - fix writerfilter XSL to handle more elements

  - missing call to importDocumentProperties. (bnc#655194)

  - rotated text DOCX import (fdo#30474)

  - impress :

  - avoid antialiasing for drag rect

  - libs-core :

  - Adapted README according to list feedback

  - register EvolutionLocal when evolution support is
    enabled (fdo#32007)

  - crash during toolpanel re-docking

  - crash in FR version when typing / as first character
    (i#115774)

  - only start the quick-starter on restart

  - don't crash when quickstarter is exited by user
    (rh#650170)

  - shutdown quickstarter at end of desktop session
    (rh#650170)

  - exit quickstarter if physically deleted (rh#610103)

  - autocorrect crasher (rh#647392)

  - start quickstarter on every launch if configured to use
    it

  - Switch toolbar icon size to 'auto-detect'

  - libs-extern :

  - Use the new stable libwp* releases as default

  - libs-extern-sys :

  - fixed urllib.urlopen in the internal python (fdo#31466)

  - libs-gui :

  - Allow the dropdown list of a combo box to be scrollable.
    (fdo#31710)

  - PDF export regression for simple RTL cases (i#115618)

  - freeze with ODP import (i#115761)

  - make toolbar icon size native-widget controlled

  - use BrOffice in pt_BR locale (fdo#31770)

  - release the clipboard after flush (i#163153)

  - l10n :

  - BrOffice in Brazil => %PRODUCTNAME_BR for win32
    installer

  - sdk :

  - correct resolveLink function (i#115310)

  - writer :

  - crash when opening File/Print dialog fixed (i#115354)

  - better enhanced fields navigation

  - allow to localize the 'My AutoText' string (i#66304)

  - table alignment set to 'From Left' when moving the
    right. (bnc#636367)

  - font color selection didn't effect new text.
    (bnc#652204)

  - column break DOC import problem. (bnc#652364)

  - build bits :

  - install branding for the welcome screen. (bnc#653519)

  - fixed URL, summary, and description for LibreOffice

  - bumped requires to libreoffice-branding-upstream >
    3.2.99.3

  - created l10n-prebuilt subpackage for prebuilt registry
    files. (bnc#651964)

  - disabled KDE3 stuff on openSUSE >= 11.2. (bnc#605472,
    bnc#621472)

  - added gcc-c++ and libxml2-devel into BuildRequires; were
    required by kdelibs3-devel before

  - updated to libreoffice-3.2.99.3 (3.3-beta3) :

  - ooo integration :

  - Merge commit 'ooo/OOO330_m13'

  - common :

  - impress ruler behaviour

  - add Title Page dialog (i#7065)

  - save 1MB on wizards per language

  - images optimized for smaller size

  - do not insert a new cell beyond the end

  - handle multiple selection for printing (i#115266)

  - remove VBAForm property and associated geometry hack
    (fdo#30856)

  - base :

  - key columns in all tables (i#114026)

  - reports executed for data display (i#114627)

  - calc :

  - non-functional select

  - defined names in Calc functions (i#79854)

  - use Ctrl-Shift-D to launch selection list

  - regression for range array input, e.g. {=A1:A5}

  - crash on importing docs with database functions

  - crash on importing named ranges on higher sheets

  - remove the 'insert new sheet' tab in read-only mode

  - incorrect display of references from the formula input
    wizard

  - new tab page 'Compatibility' in the Options dialog
    (fdo#30559)

  - components :

  - default to evolution

  - crash in scanner dialog (rh#648475)

  - extras :

  - added LibreOffice and Tango palettes

  - filters :

  - crash on unsupported .tiffs (i#93300)

  - vertical text alignment and placeholder style.
    (bnc#645116)

  - impress :

  - broken zoom behaviour

  - crash in OGL transitions

  - support for PPT newsflash slide transition

  - libs-core :

  - register EVO address book

  - more quickstarter fixes (i#108846)

  - missing media-type for ODF thumbnails

  - add credits hyperlink into about dialog

  - freeze when adding an extension (i#114933)

  - -quickstart option, and help fix (i#108846)

  - GNOME filepicker filter selection (i#112411)

  - use 'Enter Password' in all dialogs (fdo#31075)

  - add display properties to control shapes (i#112597)

  - disable user migration when SAL_DISABLE_USERMIGRATION is
    set

  - libs-gui :

  - disable KDE's crash handler

  - refresh of OLE object previews

  - adding font aliases (i#114706)

  - comparison of key events for IM

  - show Java error just once by default

  - underlining problem with Graphite fonts (i#114765)

  - saving tempfiles when locking is not supported.

  - better selection of localized font names (i#114703)

  - MetricFields SetUnit conversions (fdo#30899, bnc#610921)

  - make Presenter Screen default to the projector
    (i#112421)

  - Qt event loop integration (when Glib is used) for KDE4
    vclplug

  - writer :

  - title pages (i#i66619)

  - more RTF import/export fixes

  - tables in page styles (i#114366)

  - round-trip of DOC unhandled fields

  - double-click behavior on enhanced fields

  - leaky pStream after RTF import (fdo#31362)

  - crash when choosing starmath from start screen

  - OLE Links round-trip fixed for links as pictures

  - setup XML namespaces also for footers and headers.
    (bnc#581954)

  - switched to the LibreOffice code base,
    http://www.documentfoundation.org/

  - renamed packages from OpenOffice_org* to libreoffice*

  - updated to libreoffice-3.2.99.2 (3.3-beta2) :

  - common :

  - show menus in icons fixup

  - show all appropriate formats by default on save as
    (i#113141)

  - RenderBadPicture on multihead setups and Cairo (i#94007,
    i#111758)

  - base :

  - use correct table name (i#114246)

  - calc :

  - better performance on Excel doc import

  - components :

  - bound image controls (i#112659)

  - Appearance config dialog crasher (i#108246)

  - Euro converter didn't work with ODS (i#100686)

  - ImageURL and Graphic properties handling (i#113991)

  - extensions :

  - some reportbuilder fixes (i#114111, i#112652)

  - extras :

  - fix malformed XML file (i#111741)

  - add Croatian autocorrection (i#96706)

  - updated Hungarian standard.bau (i#112387)

  - eensgezinswoning replaces eensgezinswoning

  - add 1/2, 3/4 and 1/4 symbols to af-ZA, de, en-ZA, mn and
    pl

  - filters :

  - adjust for table::BorderLine2

  - table DOCX import crasher (rh#632236)

  - misc improvements for DOCX VML import

  - text position bug in DOC import. (bnc#532920)

  - implement import of alpha channel for RGBA .tiffs
    (fdo#30472)

  - impress :

  - improve randomisation in 'dissolve' transition

  - libs-core :

  - add in MonoSpace setting

  - print the formula itself by default

  - extension can contain compiled help (i#114008)

  - no update menu entry for bundled extensions (i#113524)

  - prevent online update for bundled extensions (i#113524)

  - make search/replace of colour names with translations
    safer (i#110142)

  - libs-gui :

  - maths brackets misformed in presentation mode (i#113400)

  - better font-name localization, i.e. en fallback
    (i#114703)

  - default to UTF-8 for HTML unless we know differently
    (i#76649)

  - writer :

  - color problem in RTF export (fdo#30604)

  - crash on export of TOC to .doc (i#112384)

  - prevent document modification while printing (i#112518)

  - dotted and dashed border types (fate#307731,
    fate#307730)

  - changes from libreoffice-3.2.99.1 (3.3-beta1) :

  - features :

  - renamed to LibreOffice

  - based on ooo330-m7

  - changed default branding

  - started to support the LibreOffice code base [all]

  - ordinal suffixes autocorrection improvements

  - updated Numbertext extension to version 0.9.3

  - support new distros Raw, LibreOfficeLinux,
    LibreOfficeMacOSX, LibreOfficeWin32

  - performance bits :

  - memory footprint during PPT import. (bnc#637925)

  - performance bug on row height adjustments. (bnc#640112)

  - common bits :

  - don't set header in DDE tables. (bnc#634517)

  - Calc bits :

  - cell content rendering [bnc#640128]

  - Excel's cell border thickness mapping. (bnc#636691)

  - relative and absolute references toggling. (bnc#634260)

  - more on the Flat MSO XML file type detection.
    (bnc#631993)

  - Writer bits :

  - SwXTextRange DOC import (i#112564)

  - table formulas DOC import. (bnc#631912)

  - input field fixes. (bnc#628098, bnc#623944)

  - OLE Links with image DOC import. (bnc#628098)

  - nested SET/FILLIN fields DOC import. (bnc#634478)

  - broken floating tables formatting in DOC import.
    (bnc#617593)

  - double-clicking on field gives 'read only' message.
    (bnc#639288)

  - OOXML bits :

  - text paragraph autofit PPTX import

  - VBA bits :

  - implicit indexes handling

  - logical operator precedence

  - column para for Range.Cells. (bnc#639297)

  - build bits :

  - update internal ICU to version 4.2.1

  - fetch 185d60944ea767075d27247c3162b3bc-unowinreg.dll

  - updated to version 3.2.98.1 (3.3-alpha1) :

  - features :

  - RTF export rewrite

  - writer navigation

  - remove obsolete Industrial icon theme

  - common bits :

  - gray read-only styles (i#85003)

  - Accelerators for OK/Cancel buttons in GTK. (bnc#608572)

  - Calc bits :

  - cell borders not saved. (bnc#612263)

  - external reference rework. (bnc#628876)

  - Flat MSO XML file type detection. (bnc#631993)

  - disable custom tab colors in high contrast mode

  - display correct field in data pilot. (bnc#629920)

  - Watch Window extension doesn't show sheet name.
    (bnc#604638)

  - Draw bits :

  - associate application/x-wpg with oodraw. (bnc#589624)

  - Impress bits :

  - More on avmedia soundhandler (i#83753, bnc#515553)

  - Writer bits :

  - ww8 styles import (i#21939)

  - hairline table borders export

  - saving new document comparison data

  - Ruby in MS Word format (i#79246)

  - OOXML :

  - better internal hlinks XLSX export. (bnc#594248)

  - numbering roundtripping issues in DOCX. (bnc#569266)

  - untis translation from EMU in PPTX import. (bnc#621739)

  - group shapes geometry calculation in PPTX import.
    (bnc#621739)

  - many other import/export fixes and improvements

  - VBA bits :

  - changes in event handling

  - more container control fixes

  - more on invalid code name import for sheet. (bnc#507768)

  - build bits :

  - update prebuilt cli dlls for OOo-3.3

  - moving ooo-build patches to ooo git sources

  - use --without-junit on Win32 and openSUSE < 11.2

  - used the prepatched OOo sources from ooo-build git

  - used mozilla-xulrunner192 for openSUSE > 11.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=507768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=515553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=532920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=581954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=589624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=594248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=604638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=608572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=612263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=621472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=621739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=628098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=628876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=629920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=631912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=631993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=634260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=634478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=634517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=636367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=636691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=640112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=640128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=645116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=647959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=649506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=650049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=652204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=652364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=652562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=654039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=654065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=657135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=660816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=663245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=664516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=665112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=665872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=667421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2935.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2936.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3450.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3451.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3452.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3453.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3454.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3702.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4253.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4643.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4082.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libboost_thread1_36_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-components");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-converter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-draw-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-en-US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-hyphen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-icon-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-impress-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-languagetool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-languagetool-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-languagetool-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-languagetool-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-languagetool-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-languagetool-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-languagetool-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-languagetool-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-languagetool-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-libs-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-libs-extern");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-libs-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-openclipart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-templates-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-templates-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-templates-labels-a4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-templates-labels-letter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-templates-presentation-layouts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-thesaurus-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-african");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-american");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-brazilian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-british");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-catalan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-czech");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-danish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-dutch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-french");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-german");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-gujarati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-hindi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-hungarian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-italian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-norsk-bokmaal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-norsk-nynorsk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-polish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-portuguese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-russian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-slovak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-spanish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-swedish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-xhosa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:myspell-zulu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-3.3.1.2.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libboost_thread1_36_0-1.36.0-11.17")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-3.3.1.2-1.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-base-3.3.1.2-1.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-base-drivers-postgresql-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-base-extensions-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-branding-SLED-3.3.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-calc-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-calc-extensions-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-components-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-converter-3.3-1.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-draw-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-draw-extensions-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-filters-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-filters-optional-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-gnome-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-ar-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-cs-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-da-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-de-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-en-GB-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-en-US-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-es-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-fr-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-gu-IN-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-hi-IN-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-hu-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-it-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-ja-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-ko-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-nl-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-pl-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-pt-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-pt-BR-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-ru-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-sv-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-zh-CN-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-zh-TW-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-hyphen-20110217-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-icon-themes-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-impress-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-impress-extensions-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-kde-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-kde4-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-af-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-ar-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-ca-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-cs-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-da-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-de-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-en-GB-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-es-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-extras-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-fi-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-fr-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-gu-IN-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-hi-IN-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-hu-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-it-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-ja-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-ko-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-nb-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-nl-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-nn-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-pl-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-pt-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-pt-BR-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-ru-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-sk-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-sv-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-xh-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-zh-CN-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-zh-TW-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-zu-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-de-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-en-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-es-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-fr-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-it-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-nl-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-pl-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-sv-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-libs-core-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-libs-extern-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-libs-gui-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-mailmerge-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-math-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-mono-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-officebean-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-openclipart-3.3-1.12.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-pyuno-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-templates-de-3.3-1.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-templates-en-3.3-1.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-templates-labels-a4-1.0.1-1.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-templates-labels-letter-1.0.1-1.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-templates-presentation-layouts-3.3-1.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-cs-20070913.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-de-20080406.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-en-20060111.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-es-20050720.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-fr-20060511.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-hu-20080319.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-nb-20080310.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-pl-20061223.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-pt-20060817.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-ru-20061016.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-sk-20080926.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-thesaurus-sv-20080609.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-ure-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-writer-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-writer-extensions-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-african-20060117-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-american-20060207-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-brazilian-20070606-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-british-20050526-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-catalan-0.1-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-czech-20060303-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-danish-20080314-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-dutch-20070603-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-french-20060914-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-german-20071211-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-gujarati-20060929-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-hindi-0.1-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-hungarian-20080315-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-italian-20050711-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-norsk-bokmaal-20080310-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-norsk-nynorsk-20080310-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-polish-20080514-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-portuguese-20020629-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-russian-20040406-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-slovak-20060724-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-spanish-20051029-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-swedish-20080821-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-xhosa-20060123-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"myspell-zulu-20060120-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-3.3.1.2.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libboost_thread1_36_0-1.36.0-11.17")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-3.3.1.2-1.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-base-3.3.1.2-1.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-base-extensions-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-branding-SLED-3.3.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-calc-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-calc-extensions-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-components-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-converter-3.3-1.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-draw-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-draw-extensions-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-filters-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-filters-optional-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-gnome-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-ar-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-cs-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-da-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-de-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-en-GB-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-en-US-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-es-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-fr-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-gu-IN-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-hi-IN-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-hu-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-it-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-ja-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-ko-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-nl-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-pl-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-pt-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-pt-BR-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-ru-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-sv-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-zh-CN-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-zh-TW-3.3.1.2-1.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-hyphen-20110217-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-icon-themes-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-impress-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-impress-extensions-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-kde-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-kde4-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-af-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-ar-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-ca-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-cs-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-da-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-de-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-en-GB-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-es-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-extras-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-fi-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-fr-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-gu-IN-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-hi-IN-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-hu-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-it-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-ja-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-ko-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-nb-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-nl-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-nn-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-pl-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-pt-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-pt-BR-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-ru-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-sk-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-sv-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-xh-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-zh-CN-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-zh-TW-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-zu-3.3.1.2-1.3.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-de-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-en-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-es-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-fr-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-it-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-nl-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-pl-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-sv-1.2-7.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-libs-core-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-libs-extern-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-libs-gui-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-mailmerge-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-math-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-mono-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-officebean-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-openclipart-3.3-1.12.12")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-pyuno-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-templates-de-3.3-1.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-templates-en-3.3-1.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-templates-labels-a4-1.0.1-1.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-templates-labels-letter-1.0.1-1.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-templates-presentation-layouts-3.3-1.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-cs-20070913.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-de-20080406.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-en-20060111.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-es-20050720.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-fr-20060511.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-hu-20080319.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-nb-20080310.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-pl-20061223.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-pt-20060817.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-ru-20061016.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-sk-20080926.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-thesaurus-sv-20080609.1-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-ure-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-writer-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-writer-extensions-3.3.1.2-1.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-african-20060117-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-american-20060207-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-brazilian-20070606-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-british-20050526-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-catalan-0.1-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-czech-20060303-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-danish-20080314-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-dutch-20070603-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-french-20060914-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-german-20071211-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-gujarati-20060929-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-hindi-0.1-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-hungarian-20080315-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-italian-20050711-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-norsk-bokmaal-20080310-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-norsk-nynorsk-20080310-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-polish-20080514-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-portuguese-20020629-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-russian-20040406-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-slovak-20060724-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-spanish-20051029-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-swedish-20080821-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-xhosa-20060123-8.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"myspell-zulu-20060120-8.21.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
