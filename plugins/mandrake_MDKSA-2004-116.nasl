#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:116. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15551);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0888", "CVE-2004-0923");
  script_xref(name:"MDKSA", value:"2004:116");

  script_name(english:"Mandrake Linux Security Advisory : cups (MDKSA-2004:116)");
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
"Chris Evans discovered numerous vulnerabilities in the xpdf package,
which also effect software using embedded xpdf code :

Multiple integer overflow issues affecting xpdf-2.0 and xpdf-3.0. Also
programs like cups which have embedded versions of xpdf. These can
result in writing an arbitrary byte to an attacker controlled location
which probably could lead to arbitrary code execution. (CVE-2004-0888)

Also, when CUPS debugging is enabled, device URIs containing username
and password end up in error_log. This information is also visible via
'ps'. (CVE-2004-0923)

The updated packages are patched to protect against these
vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cups.org/str.php?L920"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cups2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcups2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/22");
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
if (rpm_check(release:"MDK10.0", reference:"cups-1.1.20-5.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"cups-common-1.1.20-5.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"cups-serial-1.1.20-5.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64cups2-1.1.20-5.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64cups2-devel-1.1.20-5.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libcups2-1.1.20-5.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libcups2-devel-1.1.20-5.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"cups-1.1.21-0.rc1.7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"cups-common-1.1.21-0.rc1.7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"cups-serial-1.1.21-0.rc1.7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64cups2-1.1.21-0.rc1.7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64cups2-devel-1.1.21-0.rc1.7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libcups2-1.1.21-0.rc1.7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libcups2-devel-1.1.21-0.rc1.7.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"cups-1.1.19-10.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"cups-common-1.1.19-10.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"cups-serial-1.1.19-10.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64cups2-1.1.19-10.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64cups2-devel-1.1.19-10.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libcups2-1.1.19-10.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libcups2-devel-1.1.19-10.3.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
