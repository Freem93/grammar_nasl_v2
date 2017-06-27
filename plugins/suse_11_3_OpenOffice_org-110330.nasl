#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update OpenOffice_org-4262.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75687);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2010-2935", "CVE-2010-2936", "CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-3702", "CVE-2010-3704", "CVE-2010-4253", "CVE-2010-4643");

  script_name(english:"openSUSE Security Update : OpenOffice_org (openSUSE-SU-2011:0336-1)");
  script_summary(english:"Check for the OpenOffice_org-4262 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
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

  - fixed security bugs :

  - PowerPoint document processing (CVE-2010-2935,
    CVE-2010-2936)

  - extensions and filter package files (CVE-2010-3450)

  - RTF document processing (CVE-2010-3451, CVE-2010-3452)

  - Word document processing (CVE-2010-3453, CVE-2010-3454)

  - insecure LD_LIBRARY_PATH usage (CVE-2010-3689)

  - PDF Import extension resulting from 3rd party library
    XPD (CVE-2010-3702, CVE-2010-3704)

  - PNG file processing (CVE-2010-4253)

  - TGA file processing (CVE-2010-4643)

  - most important changes :

  - add conflicts to force migration to libreoffice

  - obsolete Quickstarter

  - enabled KDE3 support (bnc#678998)

  - libreoffice-3.3.1.2 == 3.3.1-rc2 == final

  - fixed audio/video playback in presentation (deb#612940,
    bnc#651250)

  - fixed non-working input methods in KDE4 (bnc#665112)

  - fixed occasional blank first slide (fdo#34533)

  - fixed cairo canvas edge count calculation (bnc#647959)

  - updated to libreoffice-3.3.1.2 (3.3.1-rc2) :

  - l10n

  - updated some translations

  - libs-core

  - crashing oosplash and malformed picture (bnc#652562)

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

  - fixed EMF+ import (bnc#650049)

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

  - pictures DOCX import (bnc#655763)

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

  - improve formfield checkbox binary export (bnc#660816)

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

  - reverted problematic and dangerous :

  - performance of filters with many filtered ranges
    (i#116164)

  - obtain correct data range for external references
    (i#115906)

  - libs-core :

  - FMR crasher (fdo#33099)

  - backgrounds for polypolygons in metafile (i#116371)

  - unopkg crasher on SLED11-SP1 (bnc#655912)

  - libs-gui :

  - use sane scrollbar sizes when drawing

  - painting of axial gradients (i#116318)

  - do not mix unrelated X11 Visuals (fdo#33108)

  - avoid GetHelpText() call which can be quite heavy

  - writer :

  - fields fixes: key inputs, 0-length fields import
    (bnc#657135)

  - replaced obsolete SuSEconfig gtk2 module call with
    %%icon_theme_cache_post(un) macros for openSUSE > 11.3
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

  - copy & paste a text formatted cell (i#115825)

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

  - removed dupe para ids introduced by copy&paste

  - colon needed for LD_LIBRARY_PATH set but empty

  - wikihelp: use the right Help ID URL (fdo#32338)

  - MySQL Cast(col1 as CHAR) yields error (i#115436)

  - import compatibility for enhanced fields names
    (fdo#32172)

  - libs-extern-sys :

  - XPATH handling fix

  - libs-gui :

  - PPTX import crasher (bnc#654065)

  - copy&paste problem of metafiles (i#115825)

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

  - empty toolbar (bnc#654039)

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

  - missing call to importDocumentProperties (bnc#655194)

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

  - table alignment set to 'From Left' when moving the right
    (bnc#636367)

  - font color selection didn't effect new text (bnc#652204)

  - column break DOC import problem (bnc#652364)

  - build bits :

  - install branding for the welcome screen (bnc#653519)

  - fixed URL, summary, and description for LibreOffice

  - bumped requires to libreoffice-branding-upstream >
    3.2.99.3

  - created l10n-prebuilt subpackage for prebuilt registry
    files (bnc#651964)

  - disabled KDE3 stuff on openSUSE >= 11.2 (bnc#605472,
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

  - vertical text alignment and placeholder style
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

  - setup XML namespaces also for footers and headers
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

  - text position bug in DOC import (bnc#532920)

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

  - memory footprint during PPT import (bnc#637925)

  - performance bug on row height adjustments (bnc#640112)

  - common bits :

  - don't set header in DDE tables (bnc#634517)

  - Calc bits :

  - cell content rendering [bnc#640128]

  - Excel's cell border thickness mapping (bnc#636691)

  - relative and absolute references toggling (bnc#634260)

  - more on the Flat MSO XML file type detection
    (bnc#631993)

  - Writer bits :

  - SwXTextRange DOC import (i#112564)

  - table formulas DOC import (bnc#631912)

  - input field fixes (bnc#628098, bnc#623944)

  - OLE Links with image DOC import (bnc#628098)

  - nested SET/FILLIN fields DOC import (bnc#634478)

  - broken floating tables formatting in DOC import
    (bnc#617593)

  - double-clicking on field gives 'read only' message
    (bnc#639288)

  - OOXML bits :

  - text paragraph autofit PPTX import

  - VBA bits :

  - implicit indexes handling

  - logical operator precedence

  - column para for Range.Cells (bnc#639297)

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

  - Accelerators for OK/Cancel buttons in GTK (bnc#608572)

  - Calc bits :

  - cell borders not saved (bnc#612263)

  - external reference rework (bnc#628876)

  - Flat MSO XML file type detection (bnc#631993)

  - disable custom tab colors in high contrast mode

  - display correct field in data pilot (bnc#629920)

  - Watch Window extension doesn't show sheet name
    (bnc#604638)

  - Draw bits :

  - associate application/x-wpg with oodraw (bnc#589624)

  - Impress bits :

  - More on avmedia soundhandler (i#83753, bnc#515553)

  - Writer bits :

  - ww8 styles import (i#21939)

  - hairline table borders export

  - saving new document comparison data

  - Ruby in MS Word format (i#79246)

  - OOXML :

  - better internal hlinks XLSX export (bnc#594248)

  - numbering roundtripping issues in DOCX (bnc#569266)

  - untis translation from EMU in PPTX import (bnc#621739)

  - group shapes geometry calculation in PPTX import
    (bnc#621739)

  - many other import/export fixes and improvements

  - VBA bits :

  - changes in event handling

  - more container control fixes

  - more on invalid code name import for sheet (bnc#507768)

  - build bits :

  - update prebuilt cli dlls for OOo-3.3

  - moving ooo-build patches to ooo git sources

  - use --without-junit on Win32 and openSUSE < 11.2

  - used the prepatched OOo sources from ooo-build git

  - used mozilla-xulrunner192 for openSUSE > 11.3
    MaintenanceTracker-35044, CVE-2010-2935, 
CVE-2010-2936) :

  - Calc bits :

  - custom field names handling in Data Pilot (bnc#634974)

  - remember 'sort by' selection in Data Pilot (bnc#634974)

  - more on the Flat MSO XML file type detection
    (bnc#631993)

  - Impress bits :

  - cairocanvas border treatment (bnc#629546, rh#557317)
    MaintenanceTracker-35044, CVE-2010-2935, 
CVE-2010-2936) :

  - security fixes :

  - two impress vulnerabilities (CVE-2010-2935,
    CVE-2010-2936, bnc#629085)

  - common bits :

  - honour ure-link in SDK configure.pl

  - macro recording crasher (i#113084) [upstream, Rene]

  - Calc bits :

  - DataPilot sort by ID (bnc#622920)

  - Flat MSO XML file type detection (bnc#527738)

  - DDE linkage upon loading documents (bnc#618846,
    bnc#618864)

  - file name as sheet name in Excel 2.1 docs import
    (bnc#612902)

  - Draw bits :

  - random extra arrows around the custom shape (i#105654)

  - Impress bits :

  - slideshow clipping (i#112422)

  - cairocanvas border treatment (bnc#629546, rh#557317)

  - Writer bits :

  - input field fixes (bnc#628098, bnc#623944)

  - non-breaking space erasing freeze (i#i113461) [upstream,
    Rene]

  - broken floating tables formatting in DOC import
    (bnc#617593)

  - Netbooks bits :

  - decorate help window (bnc#621116)

  - more restrictive top level document window check
    (bnc#607735)

  - reduce height of PDF export and recovery dialogs
    (bnc#623352)

  - Win32 bits :

  - allow view 'details' in File Open dialog on XP
    (bnc#620924)

  - l10n bits :

  - non-localized Tools/Options/OOo Writer/Comparison
    (bnc#615000)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-04/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.documentfoundation.org/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527738"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607735"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=612902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=615000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=620924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=621116"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=622920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623352"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=629085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=629546"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=634974"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=667421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678998"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenOffice_org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aspell-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ispell-naustrian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ispell-ngerman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ispell-nswiss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-artwork-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-branding-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-components");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-components-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-components-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-converter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-US-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pa-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-hyphen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-crystal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-themes-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-be-BY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en-ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-extras-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-extras-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pa-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-languagetool-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-libs-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-libs-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-libs-core-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-libs-extern");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-libs-extern-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-libs-extern-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-libs-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-libs-gui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-libs-gui-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-openclipart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-templates-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-templates-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-templates-labels-a4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-templates-labels-letter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-templates-presentation-layouts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-templates-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-testing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-testtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-de-AT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-de-CH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-en-AU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-en-US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-es-AR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-es-VE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-thesaurus-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-ure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-voikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-african");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-albanian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-american");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-arabic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-assamese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-asturian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-australian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-austrian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-belarusian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bengali");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-brazilian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-breton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-british");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bulgarian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-canadian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-catalan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-chichewa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-croatian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-czech");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-danish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-dutch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-esperanto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-estonian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-faroese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-french");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gaelic-scots");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-galician");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-german");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-greek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gujarati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-haitian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-hebrew");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-hindi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-hungarian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-icelandic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-indonese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-irish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-italian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-khmer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kichwa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kikuyu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kinyarwanda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kiswahili");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kurdish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-latvian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lithuanian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-macedonian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-maithili");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-malagasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-malay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-malayalam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-maory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-marathi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-mexican");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ndebele");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-new-zealand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-norsk-bokmaal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-norsk-nynorsk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-nswiss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-occitan-lengadocian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-persian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-polish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-portuguese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-romanian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-russian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-setswana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-slovak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-slovene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sotho-northern");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-south-african-english");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-argentine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-bolivian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-chilean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-colombian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-costa-rican");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-dominican");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-ecuadorian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-guatemalan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-honduran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-nicaraguan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-panamanian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-paraguayan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-peruvian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-puerto-rican");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-salvadorean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-uruguayan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-spanish-venezuelan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-swati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-swedish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-swedish-finland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-tagalog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-thai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-tsonga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ukrainian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-venda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-vietnamese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-welsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-xhosa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-zulu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"OpenOffice_org-3.3.1.2.1-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"aspell-de-20091006-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"ispell-naustrian-20091006-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"ispell-ngerman-20091006-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"ispell-nswiss-20091006-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-3.3.1.2-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-artwork-devel-3.3.1.2-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-base-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-base-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-base-drivers-mysql-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-base-drivers-postgresql-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-base-extensions-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-base-l10n-prebuilt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-bootstrap-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-branding-openSUSE-3.3.1-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-branding-upstream-3.3.1.2-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-calc-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-calc-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-calc-extensions-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-calc-l10n-prebuilt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-components-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-components-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-components-l10n-prebuilt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-converter-3.3-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-draw-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-draw-extensions-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-filters-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-filters-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-filters-l10n-prebuilt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-filters-optional-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-gnome-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-ar-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-cs-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-da-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-de-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-en-GB-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-en-US-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-en-US-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-en-ZA-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-es-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-et-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-fr-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-gl-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-gu-IN-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-hi-IN-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-hu-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-it-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-ja-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-km-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-ko-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-nl-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-pa-IN-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-pl-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-pt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-pt-BR-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-ru-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-sl-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-sv-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-zh-CN-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-help-zh-TW-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-hyphen-20110203.1-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-icon-theme-crystal-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-icon-theme-galaxy-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-icon-theme-hicontrast-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-icon-theme-oxygen-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-icon-theme-tango-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-icon-themes-prebuilt-3.3.1.2-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-impress-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-impress-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-impress-extensions-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-impress-l10n-prebuilt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-kde-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-kde4-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-af-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-ar-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-be-BY-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-bg-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-br-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-ca-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-cs-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-cy-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-da-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-de-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-el-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-en-GB-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-en-ZA-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-es-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-et-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-extras-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-extras-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-extras-prebuilt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-fi-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-fr-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-ga-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-gl-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-gu-IN-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-he-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-hi-IN-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-hr-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-hu-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-it-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-ja-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-ka-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-km-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-ko-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-lt-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-mk-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-nb-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-nl-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-nn-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-nr-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-pa-IN-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-pl-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-prebuilt-3.3.1.2-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-pt-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-pt-BR-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-ru-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-rw-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-sh-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-sk-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-sl-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-sr-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-ss-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-st-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-sv-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-tg-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-th-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-tr-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-ts-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-uk-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-ve-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-vi-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-xh-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-zh-CN-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-zh-TW-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-l10n-zu-3.3.1.2-2.2.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-ca-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-de-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-en-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-es-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-fr-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-gl-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-it-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-nl-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-pl-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-ro-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-ru-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-sk-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-languagetool-sv-1.2-7.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-libs-core-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-libs-core-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-libs-core-l10n-prebuilt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-libs-extern-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-libs-extern-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-libs-extern-l10n-prebuilt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-libs-gui-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-libs-gui-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-libs-gui-l10n-prebuilt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-mailmerge-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-math-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-mono-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-officebean-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-openclipart-3.3-1.12.4") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-pyuno-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-templates-de-3.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-templates-en-3.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-templates-labels-a4-1.0.1-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-templates-labels-letter-1.0.1-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-templates-presentation-layouts-3.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-templates-ru-3.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-testing-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-testtool-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-bg-20071210.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-ca-1.5.0.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-cs-20070913.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-da-20100126.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-de-20100307.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-de-AT-20100307.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-de-CH-20100307.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-el-20061203.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-en-AU-20081215.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-en-GB-20051128.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-en-US-20060111.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-es-20050720.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-es-AR-0.1.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-es-VE-1.0.1.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-fr-20100125.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-ga-20071002.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-hu-20080319.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-it-20081129.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-nb-20080310.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-ne-1.1.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-pl-20081206.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-pt-20091015.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-ro-20091130.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-ru-20081013.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-sk-20100208.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-sl-20080601.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-thesaurus-sv-20090624.1-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-ure-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-ure-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-voikko-3.1.2-8.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-writer-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-writer-devel-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-writer-extensions-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libreoffice-writer-l10n-prebuilt-3.3.1.2-2.2.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-african-20080701-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-albanian-1.6.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-american-20100316-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-arabic-20080110-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-assamese-1.0.3-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-asturian-0.0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-australian-20100316-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-austrian-20091006-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-belarusian-1.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-bengali-20080201-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-brazilian-20100111-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-breton-0.3-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-british-20100316-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-bulgarian-4.1.5-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-canadian-20100316-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-catalan-2.1.5-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-chichewa-0.01-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-croatian-20080813-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-czech-20080822-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-danish-20090925-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-dutch-20091002-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-esperanto-1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-estonian-1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-faroese-20070816-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-french-20100125-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-gaelic-scots-1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-galician-20080515-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-german-20091006-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-greek-20041220-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-gujarati-20061015-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-haitian-0.06-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-hebrew-20080914-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-hindi-20090617-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-hungarian-20100329-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-icelandic-20090823-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-indonese-1.2-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-irish-20080805-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-italian-20081129-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-khmer-1.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-kichwa-0.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-kikuyu-20091010-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-kinyarwanda-20090218-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-kiswahili-20040516-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-kurdish-0.96.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-latvian-20100419-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-lithuanian-20081204-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-macedonian-20051126-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-maithili-20100107-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-malagasy-0.03-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-malay-20090808-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-malayalam-1.1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-maory-20080630-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-marathi-20091210-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-mexican-20091103-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-ndebele-20091030-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-new-zealand-20081204-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-norsk-bokmaal-20080310-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-norsk-nynorsk-20080310-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-nswiss-20091006-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-occitan-lengadocian-0.6.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-persian-20070815-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-polish-20081206-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-portuguese-20091015-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-romanian-20091130-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-russian-20081013-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-setswana-20061023-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-slovak-20100208-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-slovene-20091130-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-sotho-northern-20060123-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-south-african-english-20100316-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-20051029-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-argentine-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-bolivian-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-chilean-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-colombian-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-costa-rican-0.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-dominican-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-ecuadorian-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-guatemalan-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-honduran-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-nicaraguan-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-panamanian-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-paraguayan-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-peruvian-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-puerto-rican-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-salvadorean-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-uruguayan-0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-spanish-venezuelan-1.0.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-swati-20091030-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-swedish-20100130-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-swedish-finland-20100131-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-tagalog-0.02-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-thai-0.3-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-tsonga-20060123-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-ukrainian-20090818-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-venda-20091030-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-vietnamese-20091031-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-welsh-20040425-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-xhosa-20091030-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"myspell-zulu-20091210-10.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenOffice_org / aspell-de / ispell-naustrian / ispell-ngerman / etc");
}
