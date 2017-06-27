#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:149. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(23896);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/17 17:02:53 $");

  script_cve_id("CVE-2006-4031", "CVE-2006-4226");
  script_bugtraq_id(19279, 19559);
  script_osvdb_id(27703, 28012);
  script_xref(name:"MDKSA", value:"2006:149");

  script_name(english:"Mandrake Linux Security Advisory : MySQL (MDKSA-2006:149)");
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
"MySQL 4.1 before 4.1.21 and 5.0 before 5.0.24 allows a local user to
access a table through a previously created MERGE table, even after
the user's privileges are revoked for the original table, which might
violate intended security policy (CVE-2006-4031).

The update allows the local admin to override MERGE using the
'--skip-merge' option when running mysqld. This can be defined under
MYSQLD_OPTIONS in /etc/sysconfig/mysqld. If '--skip-merge' is not
used, the old behaviour of MERGE tables is still used.

MySQL 4.1 before 4.1.21, 5.0 before 5.0.25, and 5.1 before 5.1.12,
when run on case-sensitive filesystems, allows remote authenticated
users to create or access a database when the database name differs
only in case from a database for which they have permissions
(CVE-2006-4226).

Packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"MySQL-4.1.12-4.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"MySQL-Max-4.1.12-4.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"MySQL-NDB-4.1.12-4.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"MySQL-bench-4.1.12-4.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"MySQL-client-4.1.12-4.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"MySQL-common-4.1.12-4.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64mysql14-4.1.12-4.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64mysql14-devel-4.1.12-4.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libmysql14-4.1.12-4.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libmysql14-devel-4.1.12-4.6.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
