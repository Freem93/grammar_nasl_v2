#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libreoffice-34-5253.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75919);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-2685", "CVE-2011-2713");
  script_osvdb_id(73314, 76178);

  script_name(english:"openSUSE Security Update : libreoffice-34 (openSUSE-SU-2011:1143-2)");
  script_summary(english:"Check for the libreoffice-34-5253 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice 3.4 includes new interesting features and fixes, see
http://www.libreoffice.org/download/3-4-new-features-and-fix es/

The update fixes the following security issue :

  - 704311: libreoffice Lotus Word Pro filter multiple
    vulnerabilities (CVE-2011-2685)

  - 722075: LibreOffice: Out-of-bounds read in DOC sprm
    (CVE-2011-2713)

This update also fixes the following non-security issues :

  - 647959: LibO has a regression problem to show emf charts
    properly.

  - 650049: pptx presentation has text in boxes and circles.
    Only text is displayed.

  - 651250: Video and Audio does not play in slide show mode
    of LibO Impress.

  - 652562: LibreOffice crashes on start on 11.4-MS3 NET/DVD
    install

  - 653662: libreoffice build calls mkbundle2 (deprecated)
    instead of mkbundle

  - 663622: Writer crash during document save

  - 665112: could not type or edit office document

  - 675868: eliminate wording of ooconvert existed in
    loconvert --help

  - 675961: Libreoffice Copy paste of formula in Writer
    tables does not work as expected

  - 676858: Document with full page graphic in header will
    not allow click-drag or right-click.

  - 678998: Libre Office 3.3.1 does not detect KDE3

  - 680272: Deleting multiple sheets results in run-time
    error/crash

  - 681738: DDE link is lost when .xls file is opened/saved
    in Calc.

  - 683578: Large xlsx file takes extremely long to open
    with Libreoffice calc

  - 684784: Microsoft Office spreadsheet does not display
    anything

  - 693238: Column format in docx file is not displayed
    correctly.

  - 693477: Format of Word .doc file from HP is bad.

  - 694119: Using File-->Send-->Document as E-mail will
    crash Impress

  - 694344: 3rd level bulleted items are not displayed
    properly.

  - 695479: L3: RTF file is not displayed correctly by
    Writer.

  - 696630: DDE link from Calc to Excel needs Excel open to
    update link in Calc.

  - 702506: Writer crashes when opening docx files.

  - 704639: HTML document appearance changes when opened in
    open office vs LibreOffice

  - 704642: 16 digit numbers change in LibreOffice when
    opening a file created in MS Excel

  - 705949: Information missing from MS Word document when
    opened in LibreOffice (w:sdt)

  - 706792: PTF 3.3.1-21 introduced a crash when opening a
    pptx presentation.

  - 707486: Macro from excel fails on Selection.Copy when
    run in Calc.

  - 707779: Disappearing text

  - 708137: xls spreadsheet is extremely slow to open and
    check boxes are broken.

  - 708518: Bullet symbol is not rendered correctly in a
    specific slide.

  - 710061: ODP export to PDF produces broken images

  - 710920: RPM installation ending with redundant error.

  - 711977: File association for fod* files are missing.

  - 712358: Some extensions broken after upgrading.

  - 715268: Command libreoffice --help does not work when
    LibreOffice is already started

  - 715856: LibreOffice:Stable/libreoffice-converter: Bug

  - 715416: Impress crashes starting Slide show in the
    context of dual monitors extension mode.

  - 715931: failed to save an odp file.

  - 717262: libtool adds /usr/lib64 into rpath"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-10/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.libreoffice.org/download/3-4-new-features-and-fix"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=647959"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=652562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=663622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=665112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=675868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=675961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=676858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=680272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=683578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=684784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=693238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=693477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=694119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=694344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=695479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=696630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=702506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=705949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=706792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=707486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=707779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=708137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=708518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=710061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=710920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=711977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=715268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=715416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=715856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=715931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=717262"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice-34 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-converter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-extensions-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-US");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-crystal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-themes-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-extensions-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-openclipart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-testtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-testtool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/07");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-base-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-base-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-base-drivers-mysql-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-base-drivers-mysql-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-base-drivers-postgresql-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-base-drivers-postgresql-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-base-extensions-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-branding-upstream-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-calc-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-calc-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-calc-extensions-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-converter-3.3-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-draw-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-draw-extensions-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-draw-extensions-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-filters-optional-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-filters-optional-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-gnome-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-gnome-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-cs-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-da-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-de-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-en-GB-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-en-US-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-en-ZA-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-es-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-et-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-fr-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-gl-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-gu-IN-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-hi-IN-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-hu-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-it-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-ja-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-km-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-ko-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-nl-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-pl-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-pt-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-pt-BR-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-ru-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-sl-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-sv-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-zh-CN-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-help-zh-TW-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-icon-theme-crystal-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-icon-theme-galaxy-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-icon-theme-hicontrast-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-icon-theme-oxygen-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-icon-theme-tango-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-icon-themes-prebuilt-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-impress-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-impress-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-impress-extensions-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-impress-extensions-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-kde4-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-kde4-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-af-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-ar-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-be-BY-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-bg-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-br-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-ca-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-cs-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-cy-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-da-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-de-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-el-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-en-GB-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-en-ZA-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-es-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-et-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-fi-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-fr-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-ga-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-gl-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-gu-IN-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-he-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-hi-IN-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-hr-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-hu-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-it-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-ja-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-ka-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-km-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-ko-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-lt-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-mk-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-nb-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-nl-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-nn-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-nr-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-pa-IN-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-pl-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-prebuilt-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-pt-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-pt-BR-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-ru-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-rw-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-sh-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-sk-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-sl-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-sr-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-ss-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-st-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-sv-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-tg-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-th-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-tr-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-ts-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-uk-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-ve-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-vi-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-xh-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-zh-CN-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-zh-TW-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-l10n-zu-3.4.2.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-ca-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-de-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-en-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-es-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-fr-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-gl-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-it-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-nl-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-pl-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-ro-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-ru-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-sk-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-languagetool-sv-1.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-mailmerge-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-math-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-math-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-officebean-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-officebean-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-openclipart-3.4-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-pyuno-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-pyuno-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-testtool-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-testtool-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-writer-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-writer-debuginfo-3.4.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreoffice-writer-extensions-3.4.2.6-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice");
}
