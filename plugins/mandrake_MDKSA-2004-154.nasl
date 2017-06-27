#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:154. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16035);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2004-1145");
  script_xref(name:"MDKSA", value:"2004:154");

  script_name(english:"Mandrake Linux Security Advisory : kdelibs (MDKSA-2004:154)");
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
"A vulnerability in the Konqueror webbrowser was discovered where an
untrusted java applet could escalate privileges (through JavaScript
calling into Java code). This includes the reading and writing of
files with the privileges of the user running the applet.

The provided packages have been patched to correct this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.heise.de/security/dienste/browsercheck/tests/java.shtml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20041220-1.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/23");
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
if (rpm_check(release:"MDK10.0", reference:"kdelibs-common-3.2-36.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdecore4-3.2-36.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdecore4-devel-3.2-36.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdecore4-3.2-36.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdecore4-devel-3.2-36.7.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"kdelibs-common-3.2.3-99.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdecore4-3.2.3-99.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdecore4-devel-3.2.3-99.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdecore4-3.2.3-99.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdecore4-devel-3.2.3-99.1.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");