#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:070. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(18032);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2004-0957");
  script_xref(name:"MDKSA", value:"2005:070");

  script_name(english:"Mandrake Linux Security Advisory : MySQL (MDKSA-2005:070)");
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
"A vulnerability in MySQL would allow a user with grant privileges to a
database with a name containing an underscore character ('_') to have
the ability to grant privileges to other databases with similar names.
This problem was previously discovered and fixed, but a new case where
the problem still existed was recently discovered.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-Max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql12-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/13");
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
if (rpm_check(release:"MDK10.0", reference:"MySQL-4.0.18-1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"MySQL-Max-4.0.18-1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"MySQL-bench-4.0.18-1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"MySQL-client-4.0.18-1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"MySQL-common-4.0.18-1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64mysql12-4.0.18-1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64mysql12-devel-4.0.18-1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libmysql12-4.0.18-1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libmysql12-devel-4.0.18-1.5.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"MySQL-4.0.20-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"MySQL-Max-4.0.20-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"MySQL-bench-4.0.20-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"MySQL-client-4.0.20-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"MySQL-common-4.0.20-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64mysql12-4.0.20-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64mysql12-devel-4.0.20-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libmysql12-4.0.20-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libmysql12-devel-4.0.20-3.4.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
