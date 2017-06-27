#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:124. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15635);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:47:36 $");

  script_cve_id("CVE-2004-0687", "CVE-2004-0688");
  script_xref(name:"MDKSA", value:"2004:124");

  script_name(english:"Mandrake Linux Security Advisory : xorg-x11 (MDKSA-2004:124)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans found several stack and integer overflows in the libXpm
code of X.Org/XFree86 :

Stack overflows (CVE-2004-0687) :

Careless use of strcat() in both the XPMv1 and XPMv2/3 xpmParseColors
code leads to a stack based overflow (parse.c).

Stack overflow reading pixel values in ParseAndPutPixels (create.c) as
well as ParsePixels (parse.c).

Integer Overflows (CVE-2004-0688) :

Integer overflow allocating colorTable in xpmParseColors (parse.c) -
probably a crashable but not exploitable offence.

Additionally, the xorg-x11 packages have been patched with a backport
from cvs to resolve a failure running the lsb-test-vsw4 test suite,
which will soon be required for LSB2.0 compliance.

The updated packages have patches from Chris Evans and Matthieu Herrb
to address these vulnerabilities."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:X11R6-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xorg-x11-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxorg-x11-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-cyrillic-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-glide-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"X11R6-contrib-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64xorg-x11-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64xorg-x11-devel-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64xorg-x11-static-devel-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libxorg-x11-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libxorg-x11-devel-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libxorg-x11-static-devel-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-100dpi-fonts-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-75dpi-fonts-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-Xnest-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-Xvfb-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-cyrillic-fonts-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-doc-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"xorg-x11-glide-module-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-server-6.7.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-xfs-6.7.0-4.1.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
