#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:159. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(62425);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/24 10:42:02 $");

  script_cve_id("CVE-2012-3547");
  script_bugtraq_id(55483);
  script_xref(name:"MDVSA", value:"2012:159");

  script_name(english:"Mandriva Linux Security Advisory : freeradius (MDVSA-2012:159)");
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

Stack-based buffer overflow in the cbtls_verify function in FreeRADIUS
2.1.10 through 2.1.12, when using TLS-based EAP methods, allows remote
attackers to cause a denial of service (server crash) and possibly
execute arbitrary code via a long not after timestamp in a client
certificate (CVE-2012-3547).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeradius-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freeradius-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freeradius-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freeradius1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreeradius-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreeradius1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", reference:"freeradius-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"freeradius-krb5-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"freeradius-ldap-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"freeradius-mysql-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"freeradius-postgresql-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"freeradius-sqlite-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"freeradius-unixODBC-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"freeradius-web-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64freeradius-devel-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64freeradius1-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libfreeradius-devel-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libfreeradius1-2.1.11-1.2-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
