#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:055. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44995);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:24 $");

  script_cve_id(
    "CVE-2009-0799",
    "CVE-2009-0800",
    "CVE-2009-1179",
    "CVE-2009-1180",
    "CVE-2009-1181",
    "CVE-2009-1182",
    "CVE-2009-1183",
    "CVE-2009-1187",
    "CVE-2009-1188",
    "CVE-2009-3603",
    "CVE-2009-3604",
    "CVE-2009-3605",
    "CVE-2009-3606",
    "CVE-2009-3607",
    "CVE-2009-3608",
    "CVE-2009-3609",
    "CVE-2009-3938"
  );
  script_bugtraq_id(
    34568,
    36703,
    36718,
    36976
  );
  script_osvdb_id(
    54467,
    54470,
    54473,
    54478,
    54481,
    54484,
    54487,
    54807,
    54808,
    59143,
    59176,
    59178,
    59180,
    59182,
    59183,
    59825,
    59936
  );
  script_xref(name:"MDVSA", value:"2010:055");

  script_name(english:"Mandriva Linux Security Advisory : poppler (MDVSA-2010:055)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An out-of-bounds reading flaw in the JBIG2 decoder allows remote
attackers to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0799).

Multiple input validation flaws in the JBIG2 decoder allows remote
attackers to execute arbitrary code via a crafted PDF file
(CVE-2009-0800).

An integer overflow in the JBIG2 decoder allows remote attackers to
execute arbitrary code via a crafted PDF file (CVE-2009-1179).

A free of invalid data flaw in the JBIG2 decoder allows remote
attackers to execute arbitrary code via a crafted PDF (CVE-2009-1180).

A NULL pointer dereference flaw in the JBIG2 decoder allows remote
attackers to cause denial of service (crash) via a crafted PDF file
(CVE-2009-1181).

Multiple buffer overflows in the JBIG2 MMR decoder allows remote
attackers to cause denial of service or to execute arbitrary code via
a crafted PDF file (CVE-2009-1182, CVE-2009-1183).

An integer overflow in the JBIG2 decoding feature allows remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code via vectors related to CairoOutputDev (CVE-2009-1187).

An integer overflow in the JBIG2 decoding feature allows remote
attackers to execute arbitrary code or cause a denial of service
(application crash) via a crafted PDF document (CVE-2009-1188).

Integer overflow in the SplashBitmap::SplashBitmap function in Xpdf
3.x before 3.02pl4 and Poppler before 0.12.1 might allow remote
attackers to execute arbitrary code via a crafted PDF document that
triggers a heap-based buffer overflow. NOTE: some of these details are
obtained from third-party information. NOTE: this issue reportedly
exists because of an incomplete fix for CVE-2009-1188 (CVE-2009-3603).

The Splash::drawImage function in Splash.cc in Xpdf 2.x and 3.x before
3.02pl4, and Poppler 0.x, as used in GPdf and kdegraphics KPDF, does
not properly allocate memory, which allows remote attackers to cause a
denial of service (application crash) or possibly execute arbitrary
code via a crafted PDF document that triggers a NULL pointer
dereference or a heap-based buffer overflow (CVE-2009-3604).

Multiple integer overflows allow remote attackers to cause a denial of
service (application crash) or possibly execute arbitrary code via a
crafted PDF file, related to (1) glib/poppler-page.cc; (2)
ArthurOutputDev.cc, (3) CairoOutputDev.cc, (4) GfxState.cc, (5)
JBIG2Stream.cc, (6) PSOutputDev.cc, and (7) SplashOutputDev.cc in
poppler/; and (8) SplashBitmap.cc, (9) Splash.cc, and (10)
SplashFTFont.cc in splash/. NOTE: this may overlap CVE-2009-0791
(CVE-2009-3605).

Integer overflow in the PSOutputDev::doImageL1Sep function in Xpdf
before 3.02pl4, and Poppler 0.x, as used in kdegraphics KPDF, might
allow remote attackers to execute arbitrary code via a crafted PDF
document that triggers a heap-based buffer overflow (CVE-2009-3606).

Integer overflow in the create_surface_from_thumbnail_data function in
glib/poppler-page.cc allows remote attackers to cause a denial of
service (memory corruption) or possibly execute arbitrary code via a
crafted PDF document that triggers a heap-based buffer overflow. NOTE:
some of these details are obtained from third-party information
(CVE-2009-3607).

Integer overflow in the ObjectStream::ObjectStream function in XRef.cc
in Xpdf 3.x before 3.02pl4 and Poppler before 0.12.1, as used in GPdf,
kdegraphics KPDF, CUPS pdftops, and teTeX, might allow remote
attackers to execute arbitrary code via a crafted PDF document that
triggers a heap-based buffer overflow (CVE-2009-3608).

Integer overflow in the ImageStream::ImageStream function in Stream.cc
in Xpdf before 3.02pl4 and Poppler before 0.12.1, as used in GPdf,
kdegraphics KPDF, and CUPS pdftops, allows remote attackers to cause a
denial of service (application crash) via a crafted PDF document that
triggers a NULL pointer dereference or buffer over-read
(CVE-2009-3609).

Buffer overflow in the ABWOutputDev::endWord function in
poppler/ABWOutputDev.cc as used by the Abiword pdftoabw utility,
allows user-assisted remote attackers to cause a denial of service and
possibly execute arbitrary code via a crafted PDF file
(CVE-2009-3938). This update provides fixes for that vulnerabilities."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-glib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-qt2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-qt4-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-glib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-qt2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-qt4-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:poppler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-devel-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-glib-devel-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-glib3-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-qt-devel-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-qt2-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-qt4-3-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-qt4-devel-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler3-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-devel-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-glib-devel-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-glib3-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-qt-devel-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-qt2-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-qt4-3-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-qt4-devel-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler3-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"poppler-0.8.7-2.4mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
