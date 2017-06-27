#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:026. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20831);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2005-0758", "CVE-2005-0953");
  script_xref(name:"MDKSA", value:"2006:026");

  script_name(english:"Mandrake Linux Security Advisory : bzip2 (MDKSA-2006:026)");
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
"A bug was found in the way that bzgrep processed file names. If a user
could be tricked into running bzgrep on a file with a special file
name, it would be possible to execute arbitrary code with the
privileges of the user running bzgrep.

As well, the bzip2 package provided with Mandriva Linux 2006 did not
the patch applied to correct CVE-2005-0953 which was previously fixed
by MDKSA-2005:091; those packages are now properly patched.

The updated packages have been patched to correct these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64bzip2_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64bzip2_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libbzip2_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libbzip2_1-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/01");
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
if (rpm_check(release:"MDK10.1", reference:"bzip2-1.0.2-20.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64bzip2_1-1.0.2-20.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64bzip2_1-devel-1.0.2-20.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libbzip2_1-1.0.2-20.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libbzip2_1-devel-1.0.2-20.4.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"bzip2-1.0.2-20.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64bzip2_1-1.0.2-20.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64bzip2_1-devel-1.0.2-20.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libbzip2_1-1.0.2-20.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libbzip2_1-devel-1.0.2-20.3.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"bzip2-1.0.3-1.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64bzip2_1-1.0.3-1.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64bzip2_1-devel-1.0.3-1.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libbzip2_1-1.0.3-1.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libbzip2_1-devel-1.0.3-1.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
