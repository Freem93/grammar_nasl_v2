#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:227. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(43851);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/06/01 00:11:05 $");

  script_cve_id("CVE-2009-3111");
  script_xref(name:"MDVSA", value:"2009:227-1");

  script_name(english:"Mandriva Linux Security Advisory : freeradius (MDVSA-2009:227-1)");
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
"A vulnerability has been found and corrected in freeradius :

The rad_decode function in FreeRADIUS before 1.1.8 allows remote
attackers to cause a denial of service (radiusd crash) via zero-length
Tunnel-Password attributes. NOTE: this is a regression error related
to CVE-2003-0967 (CVE-2009-3111).

This update provides a solution to this vulnerability.

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"freeradius-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64freeradius1-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64freeradius1-devel-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64freeradius1-krb5-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64freeradius1-ldap-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64freeradius1-mysql-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64freeradius1-postgresql-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64freeradius1-unixODBC-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfreeradius1-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfreeradius1-devel-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfreeradius1-krb5-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfreeradius1-ldap-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfreeradius1-mysql-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfreeradius1-postgresql-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfreeradius1-unixODBC-1.1.7-2.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
