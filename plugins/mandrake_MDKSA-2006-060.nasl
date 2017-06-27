#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:060. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(21149);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2006-1354");
  script_xref(name:"MDKSA", value:"2006:060");

  script_name(english:"Mandrake Linux Security Advisory : freeradius (MDKSA-2006:060)");
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
"An unspecified vulnerability in FreeRADIUS 1.0.0 up to 1.1.0 allows
remote attackers to bypass authentication or cause a denial of service
(server crash) via 'Insufficient input validation' in the EAP-MSCHAPv2
state machine module.

Updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freeradius1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freeradius1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freeradius1-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freeradius1-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freeradius1-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freeradius1-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freeradius1-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreeradius1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreeradius1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreeradius1-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreeradius1-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreeradius1-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreeradius1-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreeradius1-unixODBC");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/27");
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
if (rpm_check(release:"MDK2006.0", reference:"freeradius-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64freeradius1-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64freeradius1-devel-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64freeradius1-krb5-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64freeradius1-ldap-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64freeradius1-mysql-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64freeradius1-postgresql-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64freeradius1-unixODBC-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libfreeradius1-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libfreeradius1-devel-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libfreeradius1-krb5-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libfreeradius1-ldap-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libfreeradius1-mysql-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libfreeradius1-postgresql-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libfreeradius1-unixODBC-1.0.4-2.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
