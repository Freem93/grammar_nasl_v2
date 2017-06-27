#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:160. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(56599);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/17 17:02:55 $");

  script_cve_id("CVE-2011-1528", "CVE-2011-1529");
  script_bugtraq_id(50273);
  script_xref(name:"MDVSA", value:"2011:160");

  script_name(english:"Mandriva Linux Security Advisory : krb5 (MDVSA-2011:160)");
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
"Multiple vulnerabilities has been found and corrected in krb5 :

The krb5_ldap_lockout_audit function in the Key Distribution Center
(KDC) in MIT Kerberos 5 (aka krb5) 1.8 through 1.8.4 and 1.9 through
1.9.1, when the LDAP back end is used, allows remote attackers to
cause a denial of service (assertion failure and daemon exit) via
unspecified vectors, related to the locked_check_p function
(CVE-2011-1528).

The lookup_lockout_policy function in the Key Distribution Center
(KDC) in MIT Kerberos 5 (aka krb5) 1.8 through 1.8.4 and 1.9 through
1.9.1, when the db2 (aka Berkeley DB) or LDAP back end is used, allows
remote attackers to cause a denial of service (NULL pointer
dereference and daemon crash) via vectors that trigger certain
process_as_req errors (CVE-2011-1529).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb53-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", reference:"krb5-1.8.1-5.6mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"krb5-pkinit-openssl-1.8.1-5.6mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"krb5-server-1.8.1-5.6mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"krb5-server-ldap-1.8.1-5.6mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"krb5-workstation-1.8.1-5.6mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64krb53-1.8.1-5.6mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64krb53-devel-1.8.1-5.6mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libkrb53-1.8.1-5.6mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libkrb53-devel-1.8.1-5.6mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
