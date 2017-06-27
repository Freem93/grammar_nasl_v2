#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:114. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(21776);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2004-0941", "CVE-2004-0990");
  script_xref(name:"MDKSA", value:"2006:114-1");

  script_name(english:"Mandrake Linux Security Advisory : libwmf (MDKSA-2006:114-1)");
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
"Multiple buffer overflows in the gd graphics library (libgd) 2.0.21
and earlier may allow remote attackers to execute arbitrary code via
malformed image files that trigger the overflows due to improper calls
to the gdMalloc function. (CVE-2004-0941)

Integer overflows were reported in the GD Graphics Library (libgd)
2.0.28, and possibly other versions. These overflows allow remote
attackers to cause a denial of service and possibly execute arbitrary
code via PNG image files with large image rows values that lead to a
heap-based buffer overflow in the gdImageCreateFromPngCtx() function.
Libwmf contains an embedded copy of the GD library code.
(CVE-2004-0990)

Update :

The previous update incorrectly attributed the advisory text to
CVE-2004-0941, while it should have been CVE-2004-0990. Additional
review of the code found fixes for CVE-2004-0941 were missing and have
also been included in this update."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wmf0.2_7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wmf0.2_7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwmf0.2_7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwmf0.2_7-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64wmf0.2_7-0.2.8.3-3.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64wmf0.2_7-devel-0.2.8.3-3.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"libwmf-0.2.8.3-3.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libwmf0.2_7-0.2.8.3-3.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libwmf0.2_7-devel-0.2.8.3-3.2.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64wmf0.2_7-0.2.8.3-6.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64wmf0.2_7-devel-0.2.8.3-6.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"libwmf-0.2.8.3-6.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libwmf0.2_7-0.2.8.3-6.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libwmf0.2_7-devel-0.2.8.3-6.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
