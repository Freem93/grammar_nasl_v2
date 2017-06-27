#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:181. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24566);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:39 $");

  script_cve_id("CVE-2006-4980");
  script_xref(name:"MDKSA", value:"2006:181");

  script_name(english:"Mandrake Linux Security Advisory : python (MDKSA-2006:181)");
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
"A vulnerability in python's repr() function was discovered by Benjamin
C. Wiley Sittler. It was found that the function did not properly
handle UTF-32/UCS-4 strings, so an application that used repr() on
certin untrusted data could possibly be exploited to execute arbitrary
code with the privileges of the user running the python application.

Updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpython2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpython2.4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64python2.4-2.4.1-5.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64python2.4-devel-2.4.1-5.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libpython2.4-2.4.1-5.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libpython2.4-devel-2.4.1-5.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"python-2.4.1-5.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"python-base-2.4.1-5.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"python-docs-2.4.1-5.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tkinter-2.4.1-5.1.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64python2.4-2.4.3-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64python2.4-devel-2.4.3-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libpython2.4-2.4.3-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libpython2.4-devel-2.4.3-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"python-2.4.3-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"python-base-2.4.3-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"python-docs-2.4.3-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tkinter-2.4.3-3.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
