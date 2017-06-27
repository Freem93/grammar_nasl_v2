#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:282. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(42181);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id(
    "CVE-2009-0146",
    "CVE-2009-0147",
    "CVE-2009-0163",
    "CVE-2009-0165",
    "CVE-2009-0166",
    "CVE-2009-0195",
    "CVE-2009-0791",
    "CVE-2009-0799",
    "CVE-2009-0800",
    "CVE-2009-0949",
    "CVE-2009-1179",
    "CVE-2009-1180",
    "CVE-2009-1181",
    "CVE-2009-1182",
    "CVE-2009-1183",
    "CVE-2009-3608",
    "CVE-2009-3609"
  );
  script_bugtraq_id(
    34568,
    34571,
    34791,
    35169,
    35195,
    36703
  );
  script_osvdb_id(
    54462,
    54465,
    54466,
    54467,
    54468,
    54469,
    54470,
    54471,
    54472,
    54473,
    54476,
    54477,
    54478,
    54479,
    54480,
    54481,
    54482,
    54483,
    54484,
    54485,
    54486,
    54487,
    54488,
    54489,
    54490,
    54491,
    54495,
    54496,
    54497,
    55002,
    56176,
    59179,
    59180,
    59183,
    59824
  );
  script_xref(name:"MDVSA", value:"2009:282-1");

  script_name(english:"Mandriva Linux Security Advisory : cups (MDVSA-2009:282-1)");
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
"Multiple integer overflows in the JBIG2 decoder in Xpdf 3.02pl2 and
earlier, CUPS 1.3.9 and earlier, and other products allow remote
attackers to cause a denial of service (crash) via a crafted PDF file,
related to (1) JBIG2Stream::readSymbolDictSeg, (2)
JBIG2Stream::readSymbolDictSeg, and (3)
JBIG2Stream::readGenericBitmap. (CVE-2009-0146, CVE-2009-0147)

Integer overflow in the TIFF image decoding routines in CUPS 1.3.9 and
earlier allows remote attackers to cause a denial of service (daemon
crash) and possibly execute arbitrary code via a crafted TIFF image,
which is not properly handled by the (1) _cupsImageReadTIFF function
in the imagetops filter and (2) imagetoraster filter, leading to a
heap-based buffer overflow. (CVE-2009-0163)

Integer overflow in the JBIG2 decoder in Xpdf 3.02pl2 and earlier, as
used in Poppler and other products, when running on Mac OS X, has
unspecified impact, related to g*allocn. (CVE-2009-0165)

The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
and other products allows remote attackers to cause a denial of
service (crash) via a crafted PDF file that triggers a free of
uninitialized memory. (CVE-2009-0166)

Heap-based buffer overflow in Xpdf 3.02pl2 and earlier, CUPS 1.3.9,
and probably other products, allows remote attackers to execute
arbitrary code via a PDF file with crafted JBIG2 symbol dictionary
segments (CVE-2009-0195).

Multiple integer overflows in the pdftops filter in CUPS 1.1.17,
1.1.22, and 1.3.7 allow remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted
PDF file that triggers a heap-based buffer overflow, possibly related
to (1) Decrypt.cxx, (2) FoFiTrueType.cxx, (3) gmem.c, (4)
JBIG2Stream.cxx, and (5) PSOutputDev.cxx in pdftops/. NOTE: the
JBIG2Stream.cxx vector may overlap CVE-2009-1179. (CVE-2009-0791)

The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
Poppler before 0.10.6, and other products allows remote attackers to
cause a denial of service (crash) via a crafted PDF file that triggers
an out-of-bounds read. (CVE-2009-0799)

Multiple input validation flaws in the JBIG2 decoder in Xpdf 3.02pl2
and earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other
products allow remote attackers to execute arbitrary code via a
crafted PDF file. (CVE-2009-0800)

The ippReadIO function in cups/ipp.c in cupsd in CUPS before 1.3.10
does not properly initialize memory for IPP request packets, which
allows remote attackers to cause a denial of service (NULL pointer
dereference and daemon crash) via a scheduler request with two
consecutive IPP_TAG_UNSUPPORTED tags. (CVE-2009-0949)

Integer overflow in the JBIG2 decoder in Xpdf 3.02pl2 and earlier,
CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other products
allows remote attackers to execute arbitrary code via a crafted PDF
file. (CVE-2009-1179)

The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
Poppler before 0.10.6, and other products allows remote attackers to
execute arbitrary code via a crafted PDF file that triggers a free of
invalid data. (CVE-2009-1180)

The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
Poppler before 0.10.6, and other products allows remote attackers to
cause a denial of service (crash) via a crafted PDF file that triggers
a NULL pointer dereference. (CVE-2009-1181)

Multiple buffer overflows in the JBIG2 MMR decoder in Xpdf 3.02pl2 and
earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other
products allow remote attackers to execute arbitrary code via a
crafted PDF file. (CVE-2009-1182)

The JBIG2 MMR decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and
earlier, Poppler before 0.10.6, and other products allows remote
attackers to cause a denial of service (infinite loop and hang) via a
crafted PDF file. (CVE-2009-1183)

Two integer overflow flaws were found in the CUPS pdftops filter. An
attacker could create a malicious PDF file that would cause pdftops to
crash or, potentially, execute arbitrary code as the lp user if the
file was printed. (CVE-2009-3608, CVE-2009-3609)

This update corrects the problems.

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cups2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-qt2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-qt4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64poppler2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcups2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-qt2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-qt4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpoppler2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:poppler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"cups-1.3.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"cups-common-1.3.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"cups-serial-1.3.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64cups2-1.3.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64cups2-devel-1.3.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-devel-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-glib-devel-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-glib2-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-qt-devel-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-qt2-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-qt4-2-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler-qt4-devel-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64poppler2-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libcups2-1.3.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libcups2-devel-1.3.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-devel-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-glib-devel-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-glib2-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-qt-devel-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-qt2-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-qt4-2-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler-qt4-devel-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpoppler2-0.6-3.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-cups-1.3.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"poppler-0.6-3.5mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
