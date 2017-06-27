#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:139. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(25669);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/01 00:01:20 $");

  script_cve_id("CVE-2007-1420", "CVE-2007-2583", "CVE-2007-2691");
  script_xref(name:"MDKSA", value:"2007:139");

  script_name(english:"Mandrake Linux Security Advisory : MySQL (MDKSA-2007:139)");
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
"MySQL 5.x before 5.0.36 allows local users to cause a denial of
service (database crash) by performing information_schema table
subselects and using ORDER BY to sort a single-row result, which
prevents certain structure elements from being initialized and
triggers a NULL dereference in the filesort function. This issue does
not affect MySQL 5.0.37 in Mandriva Linux 2007.1. (CVE-2007-1420)

The in_decimal::set function in item_cmpfunc.cc in MySQL before
5.0.40, and 5.1 before 5.1.18-beta, allows context-dependent attackers
to cause a denial of service (crash) via a crafted IF clause that
results in a divide-by-zero error and a NULL pointer dereference.
(CVE-2007-2583)

MySQL before 4.1.23, 5.0.x before 5.0.42, and 5.1.x before 5.1.18 does
not require the DROP privilege for RENAME TABLE statements, which
allows remote authenticated users to rename arbitrary tables.
(CVE-2007-2691)

Updated packages have been patched to prevent the above issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-Max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-ndb-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-ndb-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-ndb-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-ndb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql15-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql15-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql15-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql15-static-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/05");
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
if (rpm_check(release:"MDK2007.0", reference:"MySQL-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"MySQL-Max-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"MySQL-bench-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"MySQL-client-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"MySQL-common-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"MySQL-ndb-extra-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"MySQL-ndb-management-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"MySQL-ndb-storage-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"MySQL-ndb-tools-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64mysql15-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64mysql15-devel-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64mysql15-static-devel-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libmysql15-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libmysql15-devel-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libmysql15-static-devel-5.0.24a-2.1mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"MySQL-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"MySQL-Max-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"MySQL-bench-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"MySQL-client-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"MySQL-common-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"MySQL-ndb-extra-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"MySQL-ndb-management-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"MySQL-ndb-storage-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"MySQL-ndb-tools-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64mysql15-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64mysql15-devel-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64mysql15-static-devel-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libmysql15-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libmysql15-devel-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libmysql15-static-devel-5.0.37-2.1mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
