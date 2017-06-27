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
  script_id(57118);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:52:01 $");

  script_cve_id("CVE-2011-2685", "CVE-2011-2713");

  script_name(english:"SuSE 11.1 Security Update : LibreOffice (SAT Patch Number 5271)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice 3.4 includes new interesting features and fixes, see
http://www.libreoffice.org/download/3-4-new-features-and-fixes/

The update fixes the following security issue :

  - 704311: libreoffice Lotus Word Pro filter multiple
    vulnerabilities. (CVE-2011-2685)

  - 722075: LibreOffice: Out-of-bounds read in DOC sprm
    (CVE-2011-2713) This update also fixes the following
    non-security issues :

  - 653519: Welcome screen missing.

  - 653662: libreoffice build calls mkbundle2 (deprecated)
    instead of mkbundle

  - 663622: Writer crash during document save

  - 675868: eliminate wording of ooconvert existed in
    loconvert --help

  - 675961: Libreoffice Copy paste of formula in Writer
    tables does not work as expected

  - 676858: Document with full page graphic in header will
    not allow click-drag or right-click.

  - 677354: The languagetool.rpm does not work as expected

  - 678998: Libre Office does not detect KDE3

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

  - 695479: RTF file is not displayed correctly by Writer.

  - 696630: DDE link from Calc to Excel needs Excel open to
    update link in Calc.

  - 699334: Presentation created in MS Office is missing
    text when opened in LibreOffice

  - 701317: xls spreadsheet macro fails with LibreOffice.

  - 702506: Writer crashes when opening docx files.

  - 704639: HTML document appearance changes when opened in
    open office vs LibreOffice

  - 704642: 16 digit numbers change in LibreOffice when
    opening a file created in MS Excel

  - 705949: Information missing from MS Word document when
    opened in LibreOffice (w:sdt)

  - 706792: crash when opening a pptx presentation.

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

  - 715416: Impress crashes starting Slide show in the
    context of dual monitors extension mode.

  - 715931: failed to save an odp file.

  - 717262: libtool adds /usr/lib64 into rpath

  - 715856: LibreOffice:Stable/libreoffice-converter: Bug

  - 677354: The languagetool.rpm does not work as expected.

  - 693200: Documents created in MS Office cause LibreOffice
    to crash

  - 693386: Documents created in MS Office bring up the
    filter selection dialog when opened with LibreOffice

  - 693427: When using QT dialogs and not LibreOffice
    dialogs causes LibreOffice to hang when attempting to
    save a document

  - 706731: VBA Macros from MS Office Spreadsheet do not
    work correct with LibreOffice 3.3.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653519"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=699334"
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
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2685.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2713.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5271.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libneon27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libneon27-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-converter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-draw-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-gnome");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-openclipart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libneon27-0.29.6-6.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-base-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-base-drivers-postgresql-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-base-extensions-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-calc-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-calc-extensions-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-converter-3.3-1.7.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-draw-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-draw-extensions-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-filters-optional-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-gnome-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-cs-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-da-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-de-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-en-GB-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-en-US-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-es-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-fr-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-gu-IN-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-hi-IN-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-hu-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-it-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-ja-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-ko-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-nl-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-pl-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-pt-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-pt-BR-3.4.2.6-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-ru-3.4.2.6-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-sv-3.4.2.6-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-zh-CN-3.4.2.6-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-help-zh-TW-3.4.2.6-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-icon-themes-3.4.2.6-0.8.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-impress-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-impress-extensions-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-kde-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-kde4-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-af-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-ar-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-ca-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-cs-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-da-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-de-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-en-GB-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-es-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-fi-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-fr-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-gu-IN-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-hi-IN-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-hu-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-it-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-ja-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-ko-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-nb-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-nl-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-nn-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-pl-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-pt-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-pt-BR-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-ru-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-sk-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-sv-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-xh-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-zh-CN-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-zh-TW-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-l10n-zu-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-de-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-en-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-es-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-fr-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-it-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-nl-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-pl-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-languagetool-sv-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-mailmerge-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-math-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-mono-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-officebean-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-openclipart-3.4-0.6.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-pyuno-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-writer-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libreoffice-writer-extensions-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libneon27-0.29.6-6.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-base-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-base-extensions-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-calc-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-calc-extensions-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-converter-3.3-1.7.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-draw-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-draw-extensions-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-filters-optional-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-gnome-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-cs-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-da-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-de-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-en-GB-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-en-US-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-es-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-fr-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-gu-IN-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-hi-IN-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-hu-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-it-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-ja-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-ko-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-nl-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-pl-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-pt-3.4.2.6-0.14.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-pt-BR-3.4.2.6-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-ru-3.4.2.6-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-sv-3.4.2.6-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-zh-CN-3.4.2.6-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-help-zh-TW-3.4.2.6-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-icon-themes-3.4.2.6-0.8.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-impress-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-impress-extensions-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-kde-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-kde4-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-af-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-ar-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-ca-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-cs-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-da-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-de-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-en-GB-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-es-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-fi-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-fr-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-gu-IN-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-hi-IN-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-hu-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-it-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-ja-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-ko-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-nb-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-nl-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-nn-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-pl-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-pt-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-pt-BR-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-ru-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-sk-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-sv-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-xh-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-zh-CN-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-zh-TW-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-l10n-zu-3.4.2.6-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-de-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-en-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-es-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-fr-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-it-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-nl-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-pl-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-languagetool-sv-1.4-2.5.10")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-mailmerge-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-math-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-mono-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-officebean-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-openclipart-3.4-0.6.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-pyuno-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-writer-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libreoffice-writer-extensions-3.4.2.6-0.14.4")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"libneon27-0.29.6-6.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libneon27-0.29.6-6.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libneon27-32bit-0.29.6-6.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
