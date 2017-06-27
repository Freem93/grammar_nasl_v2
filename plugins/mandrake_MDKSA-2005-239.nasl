#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:239. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20470);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:37 $");

  script_cve_id("CVE-2005-4604");
  script_xref(name:"MDKSA", value:"2005:239");

  script_name(english:"Mandrake Linux Security Advisory : printer-filters-utils (MDKSA-2005:239)");
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
"'newbug' discovered a local root vulnerability in the mtink binary,
which has a buffer overflow in its handling of the HOME environment
variable, allowing the possibility for a local user to gain root
privileges.

Mandriva encourages all users to upgrade immediately.

The updated packages have been patched to correct these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:foomatic-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:foomatic-db-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:foomatic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript-module-X");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gimpprint1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gimpprint1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ijs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ijs0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgimpprint1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgimpprint1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libijs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libijs0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:printer-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:printer-testpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:printer-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/30");
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
if (rpm_check(release:"MDK10.1", reference:"cups-drivers-10.1-0.2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"foomatic-db-3.0.1-0.20040828.1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"foomatic-db-engine-3.0.1-0.20040828.1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"foomatic-filters-3.0.1-0.20040828.1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ghostscript-7.07-25.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ghostscript-module-X-7.07-25.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64gimpprint1-4.2.7-8.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64gimpprint1-devel-4.2.7-8.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64ijs0-0.34-82.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64ijs0-devel-0.34-82.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libgimpprint1-4.2.7-8.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libgimpprint1-devel-4.2.7-8.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libijs0-0.34-82.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libijs0-devel-0.34-82.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"printer-filters-10.1-0.2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"printer-testpages-10.1-0.2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"printer-utils-10.1-0.2.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"cups-drivers-10.2-0.11.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"printer-filters-10.2-0.11.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"printer-utils-10.2-0.11.2.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"cups-drivers-2006-7.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"printer-filters-2006-7.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"printer-utils-2006-7.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
