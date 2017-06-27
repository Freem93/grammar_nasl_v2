#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:035. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16378);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2005-0089");
  script_xref(name:"MDKSA", value:"2005:035");

  script_name(english:"Mandrake Linux Security Advisory : python (MDKSA-2005:035)");
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
"A flaw in the python language was found by the development team. The
SimpleXMLRPCServer library module could permit remote attackers
unintended access to internals of the registered object or it's
module, or possibly even other modules. This only affects python
XML-RPC servers that use the register_instance() method to register an
object without a _dispatch() method. Servers that only use the
register_function() method are not affected.

The updated packages have been patched to prevent these problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.python.org/security/PSF-2005-001/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpython2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpython2.3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64python2.3-2.3.3-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64python2.3-devel-2.3.3-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpython2.3-2.3.3-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpython2.3-devel-2.3.3-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"python-2.3.3-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"python-base-2.3.3-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"python-docs-2.3.3-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tkinter-2.3.3-2.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64python2.3-2.3.4-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64python2.3-devel-2.3.4-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libpython2.3-2.3.4-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libpython2.3-devel-2.3.4-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"python-2.3.4-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"python-base-2.3.4-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"python-docs-2.3.4-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tkinter-2.3.4-6.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64python2.3-2.3-3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64python2.3-devel-2.3-3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libpython2.3-2.3-3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libpython2.3-devel-2.3-3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"python-2.3-3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"python-base-2.3-3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"python-docs-2.3-3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"tkinter-2.3-3.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
