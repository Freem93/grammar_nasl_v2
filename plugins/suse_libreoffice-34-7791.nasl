#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57219);
  script_version ("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/05/17 11:12:38 $");

  script_cve_id("CVE-2011-2685");

  script_name(english:"SuSE 10 Security Update : libreoffice (ZYPP Patch Number 7791)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice 3.4 includes many interesting features and fixes, see
http://www.libreoffice.org/download/3-4-new-features-and-fixes/

The update fixes the following security issues :

  - 704311: libreoffice Lotus Word Pro filter multiple
    vulnerabilities. (CVE-2011-2685)

This update also fixes the following non-security issues :

  - 676858: Document with full page graphic in header will
    not allow click-drag or right-click.

  - 681738: DDE link is lost when .xls file is opened/saved
    in Calc.

  - 683578: Large xlsx file takes extremely long to open
    with Libreoffice calc

  - 684784: Microsoft Office spreadsheet does not display
    anything

  - 693238: Column format in docx file is not displayed
    correctly.

  - 693477: Format of Word .doc file from HP is bad.

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

  - 715416: Impress crashes starting Slide show in the
    context of dual monitors extension mode.

  - 715931: failed to save an odp file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2685.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7791.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
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
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-af-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-ar-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-ca-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-cs-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-da-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-de-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-el-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-en-GB-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-es-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-fi-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-fr-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-galleries-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-gnome-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-gu-IN-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-hi-IN-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-hu-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-it-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-ja-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-kde-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-ko-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-mono-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-nb-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-nl-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-nn-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-pl-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-pt-BR-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-ru-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-sk-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-sv-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-xh-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-zh-CN-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-zh-TW-3.4.2.6-2.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-zu-3.4.2.6-2.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
