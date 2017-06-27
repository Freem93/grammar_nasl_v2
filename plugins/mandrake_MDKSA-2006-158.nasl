#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:158. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(23902);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/10/29 10:42:05 $");

  script_cve_id("CVE-2006-4380");
  script_xref(name:"MDKSA", value:"2006:158");

  script_name(english:"Mandrake Linux Security Advisory : MySQL (MDKSA-2006:158)");
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
"MySQL before 4.1.13 allows local users to cause a denial of service
(persistent replication slave crash) via a query with multiupdate and
subselects. (CVE-2006-4380)

There is a bug in the MySQL-Max (and MySQL) init script where the
script was not waiting for the mysqld daemon to fully stop. This
impacted the restart behavior during updates, as well as scripted
setups that temporarily stopped the server to backup the database
files. (Bug #15724)

The Corporate 3 and MNF2 products are not affected by these issues.

Packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-Max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-NDB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql14-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql14-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"MySQL-4.1.12-4.8.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"MySQL-Max-4.1.12-4.8.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"MySQL-NDB-4.1.12-4.8.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"MySQL-bench-4.1.12-4.8.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"MySQL-client-4.1.12-4.8.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"MySQL-common-4.1.12-4.8.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64mysql14-4.1.12-4.8.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64mysql14-devel-4.1.12-4.8.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libmysql14-4.1.12-4.8.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libmysql14-devel-4.1.12-4.8.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
