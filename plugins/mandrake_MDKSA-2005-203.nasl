#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:203. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20438);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/31 23:51:58 $");

  script_cve_id("CVE-2005-2958");
  script_xref(name:"MDKSA", value:"2005:203");

  script_name(english:"Mandrake Linux Security Advisory : gda2.0 (MDKSA-2005:203)");
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
"Steve Kemp discovered two format string vulnerabilities in libgda2,
the GNOME Data Access library for GNOME2, which may lead to the
execution of arbitrary code in programs that use this library.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gda2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gda2.0-bdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gda2.0-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gda2.0-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gda2.0-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gda2.0-postgres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gda2.0-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gda2.0-xbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gda2.0_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gda2.0_3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgda2.0_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgda2.0_3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
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
if (rpm_check(release:"MDK10.2", reference:"gda2.0-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gda2.0-bdb-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gda2.0-ldap-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gda2.0-mysql-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gda2.0-odbc-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gda2.0-postgres-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gda2.0-sqlite-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gda2.0-xbase-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64gda2.0_3-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64gda2.0_3-devel-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libgda2.0_3-1.2.1-1.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libgda2.0_3-devel-1.2.1-1.2.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"gda2.0-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"gda2.0-bdb-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"gda2.0-ldap-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"gda2.0-mysql-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"gda2.0-odbc-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"gda2.0-postgres-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"gda2.0-sqlite-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"gda2.0-xbase-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64gda2.0_3-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64gda2.0_3-devel-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libgda2.0_3-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libgda2.0_3-devel-1.2.2-2.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
