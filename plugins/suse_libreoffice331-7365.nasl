#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(52738);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/06/14 20:15:06 $");

  script_cve_id("CVE-2010-2935", "CVE-2010-2936", "CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-3702", "CVE-2010-3704", "CVE-2010-4253", "CVE-2010-4643");

  script_name(english:"SuSE 10 Security Update : Libreoffice (ZYPP Patch Number 7365)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Maintenance update to LibreOffice-3.3.1. It adds some interesting
features, fixes many bugs, including several security vulnerabilities.

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

  - fixed several security bugs: o PowerPoint document
    processing (CVE-2010-2935 / CVE-2010-2936) o extensions
    and filter package files (CVE-2010-3450) o RTF document
    processing (CVE-2010-3451 / CVE-2010-3452) o Word
    document processing (CVE-2010-3453 / CVE-2010-3454) o
    insecure LD_LIBRARY_PATH usage (CVE-2010-3689) o PDF
    Import extension resulting from 3rd party library XPD
    (CVE-2010-3702 / CVE-2010-3704) o PNG file processing
    (CVE-2010-4253) o TGA file processing. (CVE-2010-4643)

  - libreoffice-3.3.1.2 == 3.3.1-rc2 == final

  - fixed audio/video playback in presentation (deb#612940,
    bnc#651250)

  - fixed non-working input methods in KDE4. (bnc#665112)

  - fixed occasional blank first slide (fdo#34533)

  - fixed cairo canvas edge count calculation. (bnc#647959)

  - defuzzed piece-packimages.diff to apply

  - updated to libreoffice-3.3.1.2 (3.3.1-rc2): o l10n

  - updated some translations o libs-core

  - crashing oosplash and malformed picture. (bnc#652562)

  - Byref and declare Basic statement (fdo#33964, i#115716)

  - fixed BorderLine(2) conversion to SvxBorderLine
    (fdo#34226) o libs-gui

  - getEnglishSearchFontName() searches Takao fonts o sdk

  - fix ODK settings.mk to only set STLPORTLIB if needed o
    writer

  - rtfExport::HackIsWW8OrHigher(): return true (fdo#33478)

  - visual editor destroys formulas containing symbols
    (fdo#32759, fdo#32755)

  - enabled KDE4 support for SLED11; LO-3.3.1 fixed the
    remaining annoying bugs

  - fixed EMF+ import. (bnc#650049)

  - updated to libreoffice-3.3.1.1 (3.3.1-rc1): o artwork

  - new MIME type icons for LibreOffice o bootstrap

  - wrong line break with ( (fdo#31271) o build

  - default formula string (n#664516)

  - don't version the bundled ct2n extension

  - last update of translations from Pootle for 3.3.1 o calc

  - import of cell attributes from Excel documents

  - incorrect page number in page preview mode (fdo#33155) o
    components

  - remove pesky on-line registration menu entry (fdo#33112)

  - crash on changing position of drawing object in header
    (rhbz#673819) o extras

  - start using technical.dic instead of oracle.dic
    (fdo#31798) o filters

  - pictures DOCX import. (bnc#655763)

  - parse 'color' property (fdo#33551)

  - fix ole object import for writer (DOCX) (fdo#33237) o
    help

  - OOo -> LibO on Getting Support page (fdo#33249) o
    libs-core

  - handle css::table::BorderLine

  - add preferred Malayalam fonts (fdo#32953)

  - fix KDE3 library search order (fdo#32797)

  - StarDesktop.terminate macro behaviour (#30879)

  - Sun Microsystems -> TDF in desktop file (fdo#31191)

  - fixed several crashes around config UNO API (fdo#33994)

  - implementation names weren't matching with xcu
    (fdo#32872)

  - improve the check for existence of the localized help
    (fdo#33258) o libs-extern

  - upgrade libwpd to 0.9.1 o libs-gui

  - painting of axial gradients (116318)

  - fix wrong collation for Catalan language

  - crash when moving through database types (fdo#32561)

  - paint toolbar handle positioned properly (fdo#32558)

  - remove the menu when Left Alt Key was pressed; for GTK

  - default currency for Estonia should be Euro (fdo#33160)

  - year of era in long format for zh_TW by default
    (fdo#33459) o writer

  - use standard Edit button width of 50 (fdo#32633)

  - improve formfield checkbox binary export. (bnc#660816)

  - infinite loop while exporting some files in DOC/DOCX/RTF

  - CTL/Other Default Font (i#25247, i#25561, i#48064,
    i#92341)

  - libreoffice-build-3.3.0.4 == 3.3.0-rc4 == final

  - updated to libreoffice-3.3.0.4 (3.3-rc4): o common :

  - remove pesky on-line registration menu entry (fdo#33112)
    o artwork :

  - fix search toolbar up/down search button icons o base :

  - report builder not shows properties on report fields
    (fdo#32742)

  - report left/right page margin setting ignored on 64-bit
    (i#116187) o build :

  - updated translations o calc :

  - reverted problematic and dangerous: # performance of
    filters with many filtered ranges (i#116164) # obtain
    correct data range for external references (i#115906) o
    libs-core :

  - FMR crasher (fdo#33099)

  - backgrounds for polypolygons in metafile (i#116371)

  - unopkg crasher on SLED11-SP1 (bnc#655912) o libs-gui :

  - use sane scrollbar sizes when drawing

  - painting of axial gradients (i#116318)

  - do not mix unrelated X11 Visuals (fdo#33108)

  - avoid GetHelpText() call which can be quite heavy o
    writer :

  - fields fixes: key inputs, 0-length fields import.
    (bnc#657135)

  - replaced obsolete SuSEconfig gtk2 module call with
    %%icon_theme_cache_post(un) macros for openSUSE > 11.3.
    (bnc#663245)

  - updated to libreoffice-3.3.0.3 (3.3-rc3): o build :

  - use libreoffice and lo* wrappers; update man pages
    accordingly

  - navigation buttons' patch selection handling (fdo#32380,
    bnc#649506) o calc :

  - bogus check for numerical sheet names (fdo#32570)

  - performance of filters with many filtered ranges
    (i#116164)

  - obtain correct data range for external references
    (i#115906)

  - avoid double-paste when pasting text into cell comment
    (fdo#32572) o components :

  - fix nsplugin for LibreOffice name

  - fixing large OOXML files (i#115944)

  - layout breakage for KDE, X11 and (possibly) Mac
    (fdo#32133) o extensions :

  - patching xpdf to patchlevel 3.02pl5 o extras :

  - creating technical.dic based on src/*.dic o filters :

  - small TGAReader improvement (i#164349)

  - PageRange handling in writer PDF export (#116085) o
    impress :

  - missing font color (rhbz#663857)

  - use updated anchor for group shapes (i#115898)

  - presentation objects on master pages (i#115993) o
    libs-core :

  - survive missing window (rhbz#666216)

  - better font selection in Japanese locale.

  - do not block when launching Firefox (fdo#32427)

  - show the license information in a separate dialog
    (fdo#32563)

  - make unopkg --suppress-license skip license in all cases
    (fdo#32840) o libs-extern-sys :

  - better XPATH handling (i#164350) o libs-gui :

  - use the initial language if not specified (fdo#32523)

  - clean up search cache singleton in correct order
    (rhbz#666088) o writer :

  - undo/redo crash with postits (rhbz#660342)

  - rearrange title dialog to get translations (fdo#32633)

  - move to the next record during mail merge (fdo#32790)

  - updated to libreoffice-3.3.0.2 (3.3-rc2): o common :

  - copy &amp; paste a text formatted cell (i#115825)

  - replaced http://www.openoffice.org (fdo#32169) o
    bootstrap :

  - check if KDE is >= 4.2

  - cleanup unfortunate license duplication o calc :

  - ignore preceding spaces when parsing numbers

  - make the string 'New Record' localizable (fdo#32209)

  - remove trailing spaces too when parsing CSV simple
    numbers

  - display correct record information in Data Form dialog
    (fdo#32196) o components :

  - make the ODMA check box clickable again (fdo#32132)

  - fixed the sizes of Tips and Extended tips check boxes

  - make 'Reset help agent' button clickable again
    (fdo#32132) o extensions :

  - fix filled polygons on PDF import o filters :

  - performance for import of XLSX files with drawing
    objects (i#115940) o impress :

  - missing embedded object in ODP export (i#115898)

  - grey as default color for native tables in Impress

  - graphics on master page cannot be deleted (i#115993) o
    libs-core :

  - save with the proper DOC variant (fdo#32219)

  - removed dupe para ids introduced by copy&amp;paste

  - colon needed for LD_LIBRARY_PATH set but empty

  - wikihelp: use the right Help ID URL (fdo#32338)

  - MySQL Cast(col1 as CHAR) yields error (i#115436)

  - import compatibility for enhanced fields names
    (fdo#32172) o libs-extern-sys :

  - XPATH handling fix o libs-gui :

  - PPTX import crasher. (bnc#654065)

  - copy&amp;paste problem of metafiles (i#115825)

  - force Qt paint system to native (fdo#30991)

  - display problem with Vegur font (fdo#31243)

  - URIs must be exported as 7bit ASCII (i#115788)

  - regression in WMF text rendering (fdo#32236, i#115825) o
    postprocess :

  - only register EvolutionLocal when EVO support is enabled
    (fdo#32007) o writer :

  - after 'data to fields' mail merge does not work
    (fdo#31190)

  - missing outline feature in new RTF export filter
    (fdo#32039)

  - encoding of Greek letters names with accent in French
    (i#115956) o build bits :

  - better build identification in the about dialog

  - updated to libreoffice-3.3.0.1 (3.3-rc1): o ooo
    integration :

  - Merge commit 'ooo/OOO330_m17' into libreoffice-3-3 o
    common :

  - more RTF import/export fixes

  - updated branding for rc o artwork :

  - fixed icons with PNG optimizations

  - remove remaining ODF MIME type icons o bootstrap :

  - Add BrOffice artwork / branding support

  - Do not install HTML versions of LICENSE and README

  - install credits file o build :

  - empty toolbar. (bnc#654039)

  - pack PostgreSQL driver as .oxt instead of .zip o calc :

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

  - skip hidden cells while expanding range selection o
    components :

  - overlapping controls

  - bad alloc and convert to ZipIOException (rh#656191)

  - divide by zero (rh#657628) o extras :

  - use consistent autocorrect file names o filters :

  - fix writerfilter XSL to handle more elements

  - missing call to importDocumentProperties. (bnc#655194)

  - rotated text DOCX import (fdo#30474) o impress :

  - avoid antialiasing for drag rect o libs-core :

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

  - Switch toolbar icon size to 'auto-detect' o 
libs-extern :

  - Use the new stable libwp* releases as default o
    libs-extern-sys :

  - fixed urllib.urlopen in the internal python (fdo#31466)
    o libs-gui :

  - Allow the dropdown list of a combo box to be scrollable.
    (fdo#31710)

  - PDF export regression for simple RTL cases (i#115618)

  - freeze with ODP import (i#115761)

  - make toolbar icon size native-widget controlled

  - use BrOffice in pt_BR locale (fdo#31770)

  - release the clipboard after flush (i#163153) o l10n :

  - BrOffice in Brazil => %PRODUCTNAME_BR for win32
    installer o sdk :

  - correct resolveLink function (i#115310) o writer :

  - crash when opening File/Print dialog fixed (i#115354)

  - better enhanced fields navigation

  - allow to localize the 'My AutoText' string (i#66304)

  - table alignment set to 'From Left' when moving the
    right. (bnc#636367)

  - font color selection didn't effect new text.
    (bnc#652204)

  - column break DOC import problem (bnc#652364) o build
    bits :

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

  - updated to libreoffice-3.2.99.3 (3.3-beta3): o ooo
    integration :

  - Merge commit 'ooo/OOO330_m13' o common :

  - impress ruler behaviour

  - add Title Page dialog (i#7065)

  - save 1MB on wizards per language

  - images optimized for smaller size

  - do not insert a new cell beyond the end

  - handle multiple selection for printing (i#115266)

  - remove VBAForm property and associated geometry hack
    (fdo#30856) o base :

  - key columns in all tables (i#114026)

  - reports executed for data display (i#114627) o calc :

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
    (fdo#30559) o components :

  - default to evolution

  - crash in scanner dialog (rh#648475) o extras :

  - added LibreOffice and Tango palettes o filters :

  - crash on unsupported .tiffs (i#93300)

  - vertical text alignment and placeholder style
    (bnc#645116) o impress :

  - broken zoom behaviour

  - crash in OGL transitions

  - support for PPT newsflash slide transition o libs-core :

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
    set o libs-gui :

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
    vclplug o writer :

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

  - updated to libreoffice-3.2.99.2 (3.3-beta2): o common :

  - show menus in icons fixup

  - show all appropriate formats by default on save as
    (i#113141)

  - RenderBadPicture on multihead setups and Cairo (i#94007,
    i#111758) o base :

  - use correct table name (i#114246) o calc :

  - better performance on Excel doc import o components :

  - bound image controls (i#112659)

  - Appearance config dialog crasher (i#108246)

  - Euro converter didn't work with ODS (i#100686)

  - ImageURL and Graphic properties handling (i#113991) o
    extensions :

  - some reportbuilder fixes (i#114111, i#112652) o extras :

  - fix malformed XML file (i#111741)

  - add Croatian autocorrection (i#96706)

  - updated Hungarian standard.bau (i#112387)

  - eensgezinswoning replaces eensgezinswoning

  - add 1/2, 3/4 and 1/4 symbols to af-ZA, de, en-ZA, mn and
    pl o filters :

  - adjust for table::BorderLine2

  - table DOCX import crasher (rh#632236)

  - misc improvements for DOCX VML import

  - text position bug in DOC import. (bnc#532920)

  - implement import of alpha channel for RGBA .tiffs
    (fdo#30472) o impress :

  - improve randomisation in 'dissolve' transition o
    libs-core :

  - add in MonoSpace setting

  - print the formula itself by default

  - extension can contain compiled help (i#114008)

  - no update menu entry for bundled extensions (i#113524)

  - prevent online update for bundled extensions (i#113524)

  - make search/replace of colour names with translations
    safer (i#110142) o libs-gui :

  - maths brackets misformed in presentation mode (i#113400)

  - better font-name localization, i.e. en fallback
    (i#114703)

  - default to UTF-8 for HTML unless we know differently
    (i#76649) o writer :

  - color problem in RTF export (fdo#30604)

  - crash on export of TOC to .doc (i#112384)

  - prevent document modification while printing (i#112518)

  - dotted and dashed border types (fate#307731,
    fate#307730)

  - changes from libreoffice-3.2.99.1 (3.3-beta1): o
    features :

  - renamed to LibreOffice

  - based on ooo330-m7

  - changed default branding

  - started to support the LibreOffice code base [all]

  - ordinal suffixes autocorrection improvements

  - updated Numbertext extension to version 0.9.3

  - support new distros Raw, LibreOfficeLinux,
    LibreOfficeMacOSX, LibreOfficeWin32 o performance bits :

  - memory footprint during PPT import. (bnc#637925)

  - performance bug on row height adjustments (bnc#640112) o
    common bits :

  - don't set header in DDE tables (bnc#634517) o Calc 
bits :

  - cell content rendering [bnc#640128] o Excel's cell
    border thickness mapping. (bnc#636691)

  - relative and absolute references toggling (bnc#634260) o
    more on the Flat MSO XML file type detection
    (bnc#631993) o Writer bits :

  - SwXTextRange DOC import (i#112564) o table formulas DOC
    import (bnc#631912) o input field fixes (bnc#628098,
    bnc#623944) o OLE Links with image DOC import
    (bnc#628098) o nested SET/FILLIN fields DOC import
    (bnc#634478) o broken floating tables formatting in DOC
    import. (bnc#617593)

  - double-clicking on field gives 'read only' message
    (bnc#639288) o OOXML bits :

  - text paragraph autofit PPTX import o VBA bits :

  - implicit indexes handling

  - logical operator precedence

  - column para for Range.Cells (bnc#639297) o build bits :

  - update internal ICU to version 4.2.1

  - fetch 185d60944ea767075d27247c3162b3bc-unowinreg.dll

  - updated to version 3.2.98.1 (3.3-alpha1): o features :

  - RTF export rewrite

  - writer navigation

  - remove obsolete Industrial icon theme o common bits :

  - gray read-only styles (i#85003)

  - Accelerators for OK/Cancel buttons in GTK (bnc#608572) o
    Calc bits :

  - cell borders not saved. (bnc#612263)

  - external reference rework. (bnc#628876)

  - Flat MSO XML file type detection. (bnc#631993)

  - disable custom tab colors in high contrast mode

  - display correct field in data pilot. (bnc#629920)

  - Watch Window extension doesn't show sheet name
    (bnc#604638) o Draw bits :

  - associate application/x-wpg with oodraw (bnc#589624) o
    Impress bits :

  - More on avmedia soundhandler (i#83753, bnc#515553) o
    Writer bits :

  - ww8 styles import (i#21939)

  - hairline table borders export

  - saving new document comparison data

  - Ruby in MS Word format (i#79246) o OOXML :

  - better internal hlinks XLSX export. (bnc#594248)

  - numbering roundtripping issues in DOCX. (bnc#569266)

  - untis translation from EMU in PPTX import. (bnc#621739)

  - group shapes geometry calculation in PPTX import.
    (bnc#621739)

  - many other import/export fixes and improvements o VBA
    bits :

  - changes in event handling

  - more container control fixes

  - more on invalid code name import for sheet (bnc#507768)
    o build bits :

  - update prebuilt cli dlls for OOo-3.3

  - moving ooo-build patches to ooo git sources

  - use --without-junit on Win32 and openSUSE < 11.2

  - used the prepatched OOo sources from ooo-build git

  - used mozilla-xulrunner192 for openSUSE > 11.3"
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
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7365.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:3, reference:"boost-1.33.1-17.13.2.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-af-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-ar-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-ca-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-cs-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-da-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-de-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-de-templates-8.2.1-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-el-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-en-GB-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-es-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-fi-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-fr-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-galleries-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-gnome-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-gu-IN-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-hi-IN-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-hu-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-it-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-ja-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-kde-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-ko-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-mono-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-nb-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-nl-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-nn-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-pl-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-pt-BR-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-ru-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-sk-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-sv-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-xh-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-zh-CN-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-zh-TW-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libreoffice-zu-3.3.1.2-1.6.2.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-african-20040727-33.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-american-20040623-33.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-brazilian-20020806-33.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-british-20050526-27.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-catalan-0.1-248.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-czech-20030907-59.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-danish-20050421-27.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-dutch-20050719-22.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-french-1.0.1.1-26.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-german-20051213-19.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-greek-20041220-26.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-gujarati-20060929-20.12.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-hindi-0.1-20.12.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-italian-20050711-22.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-lithuanian-20031231-26.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-marathi-0.1-20.12.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-norsk-bokmaal-20050308-22.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-norsk-nynorsk-20041208-26.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-polish-20051016-20.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-portuguese-20020629-243.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-russian-20040406-28.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-slovak-20050901-20.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-slovene-20030907-54.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-spanish-20051029-20.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-swedish-20061207-1.12.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-xhosa-20060123-20.12.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"myspell-zulu-0.2-26.14.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"boost-32bit-1.33.1-17.13.2.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"boost-1.33.1-17.13.2.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"boost-32bit-1.33.1-17.13.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
