#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:028. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(36399);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/19 14:49:27 $");

  script_cve_id("CVE-2007-2692", "CVE-2007-6303", "CVE-2007-6304");
  script_bugtraq_id(24011, 26832);
  script_xref(name:"MDVSA", value:"2008:028");

  script_name(english:"Mandriva Linux Security Advisory : mysql (MDVSA-2008:028)");
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
"The mysql_change_db() function in MySQL 5.0.x before 5.0.40 did not
restore THD::db_access privileges when returning from SQL SECURITY
INVOKER stored routines, which allowed remote authenticated users to
gain privileges (CVE-2007-2692).

The federated engine in MySQL 5.0.x, when performing a certain SHOW
TABLE STATUS query, did not properly handle a response with a small
number of columns, which could allow a remote MySQL server to cause a
denial of service (federated handler crash and daemon crash) via a
response that lacks the minimum required number of columns
(CVE-2007-6304).

The updated packages provide MySQL 5.0.45 for all Mandriva Linux
platforms that shipped with MySQL 5.0.x which offers a number of
feature enhancements and bug fixes. In addition, the updates for
Corporate Server 4.0 include support for the Sphinx engine.

Please note that due to the package name change (from 'MySQL' to
'mysql'), the mysqld service will not restart automatically so users
must execute 'service mysqld start' after the upgrade is complete."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64mysql-devel-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64mysql-static-devel-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64mysql15-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libmysql-devel-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libmysql-static-devel-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libmysql15-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mysql-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mysql-bench-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mysql-client-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mysql-common-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mysql-max-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mysql-ndb-extra-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mysql-ndb-management-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mysql-ndb-storage-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mysql-ndb-tools-5.0.45-8.1mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64mysql-devel-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64mysql-static-devel-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64mysql15-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libmysql-devel-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libmysql-static-devel-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libmysql15-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mysql-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mysql-bench-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mysql-client-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mysql-common-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mysql-max-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mysql-ndb-extra-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mysql-ndb-management-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mysql-ndb-storage-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mysql-ndb-tools-5.0.45-8.1mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
