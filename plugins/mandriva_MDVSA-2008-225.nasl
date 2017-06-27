#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:225. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(36859);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/17 17:02:53 $");

  script_cve_id("CVE-2008-4309");
  script_bugtraq_id(32020);
  script_xref(name:"MDVSA", value:"2008:225");

  script_name(english:"Mandriva Linux Security Advisory : net-snmp (MDVSA-2008:225)");
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
"A denial of service vulnerability was discovered in how Net-SNMP
processed GETBULK requests. A remote attacker with read access to the
SNMP server could issue a specially crafted request which would cause
snmpd to crash (CVE-2008-4309).

Please note that for this to be successfully exploited, an attacker
must have read access to the SNMP server. By default, the public
community name grants read-only access, however it is recommended that
the default community name be changed in production.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64net-snmp-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64net-snmp15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnet-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnet-snmp-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnet-snmp15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:net-snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:net-snmp-tkmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:net-snmp-trapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-NetSNMP");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64net-snmp-devel-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64net-snmp-static-devel-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64net-snmp15-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libnet-snmp-devel-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libnet-snmp-static-devel-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libnet-snmp15-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"net-snmp-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"net-snmp-mibs-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"net-snmp-trapd-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"net-snmp-utils-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"perl-NetSNMP-5.4.1-1.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64net-snmp-devel-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64net-snmp-static-devel-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64net-snmp15-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libnet-snmp-devel-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libnet-snmp-static-devel-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libnet-snmp15-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"net-snmp-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"net-snmp-mibs-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"net-snmp-tkmib-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"net-snmp-trapd-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"net-snmp-utils-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"perl-NetSNMP-5.4.1-5.2mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64net-snmp-devel-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64net-snmp-static-devel-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64net-snmp15-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnet-snmp-devel-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnet-snmp-static-devel-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnet-snmp15-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"net-snmp-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"net-snmp-mibs-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"net-snmp-tkmib-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"net-snmp-trapd-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"net-snmp-utils-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"perl-NetSNMP-5.4.2-2.1mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
