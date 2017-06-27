#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:056. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(53227);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/07/01 13:30:48 $");

  script_cve_id("CVE-2011-1024", "CVE-2011-1025", "CVE-2011-1081");
  script_bugtraq_id(46363, 46831);
  script_xref(name:"MDVSA", value:"2011:056");

  script_name(english:"Mandriva Linux Security Advisory : openldap (MDVSA-2011:056)");
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
"Multiple vulnerabilities has been identified and fixed in openldap :

chain.c in back-ldap in OpenLDAP 2.4.x before 2.4.24, when a
master-slave configuration with a chain overlay and
ppolicy_forward_updates (aka authentication-failure forwarding) is
used, allows remote authenticated users to bypass external-program
authentication by sending an invalid password to a slave server
(CVE-2011-1024).

bind.cpp in back-ndb in OpenLDAP 2.4.x before 2.4.24 does not require
authentication for the root Distinguished Name (DN), which allows
remote attackers to bypass intended access restrictions via an
arbitrary password (CVE-2011-1025).

modrdn.c in slapd in OpenLDAP 2.4.x before 2.4.24 allows remote
attackers to cause a denial of service (daemon crash) via a relative
Distinguished Name (DN) modification request (aka MODRDN operation)
that contains an empty value for the OldDN field (CVE-2011-1081).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ldap2.4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ldap2.4_2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ldap2.4_2-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libldap2.4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libldap2.4_2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libldap2.4_2-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openldap-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openldap-testprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openldap-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ldap2.4_2-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ldap2.4_2-devel-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ldap2.4_2-static-devel-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libldap2.4_2-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libldap2.4_2-devel-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libldap2.4_2-static-devel-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openldap-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openldap-clients-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openldap-doc-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openldap-servers-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openldap-testprogs-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openldap-tests-2.4.19-2.2mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64ldap2.4_2-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64ldap2.4_2-devel-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64ldap2.4_2-static-devel-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libldap2.4_2-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libldap2.4_2-devel-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libldap2.4_2-static-devel-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openldap-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openldap-clients-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openldap-doc-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openldap-servers-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openldap-testprogs-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openldap-tests-2.4.22-2.2mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
