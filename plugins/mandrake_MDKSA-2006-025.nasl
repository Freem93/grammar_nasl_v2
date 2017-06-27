#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:025. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20819);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/06/03 19:49:35 $");

  script_cve_id("CVE-2005-1740", "CVE-2005-2177");
  script_bugtraq_id(13715);
  script_xref(name:"MDKSA", value:"2006:025");

  script_name(english:"Mandrake Linux Security Advisory : net-snmp (MDKSA-2006:025)");
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
"The fixproc application in Net-SNMP creates temporary files with
predictable file names which could allow a malicious local attacker to
change the contents of the temporary file by exploiting a race
condition, which could possibly lead to the execution of arbitrary
code. As well, a local attacker could create symbolic links in the
/tmp directory that point to a valid file that would then be
overwritten when fixproc is executed (CVE-2005-1740).

A remote Denial of Service vulnerability was also discovered in the
SNMP library that could be exploited by a malicious SNMP server to
crash the agent, if the agent uses TCP sockets for communication
(CVE-2005-2177).

The updated packages have been patched to correct these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64net-snmp5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64net-snmp5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64net-snmp5-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnet-snmp5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnet-snmp5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnet-snmp5-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:net-snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:net-snmp-trapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-NetSNMP");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/29");
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
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64net-snmp5-5.1.2-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64net-snmp5-devel-5.1.2-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64net-snmp5-static-devel-5.1.2-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnet-snmp5-5.1.2-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnet-snmp5-devel-5.1.2-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnet-snmp5-static-devel-5.1.2-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"net-snmp-5.1.2-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"net-snmp-mibs-5.1.2-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"net-snmp-trapd-5.1.2-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"net-snmp-utils-5.1.2-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-NetSNMP-5.1.2-6.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64net-snmp5-5.2.1-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64net-snmp5-devel-5.2.1-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64net-snmp5-static-devel-5.2.1-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libnet-snmp5-5.2.1-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libnet-snmp5-devel-5.2.1-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libnet-snmp5-static-devel-5.2.1-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"net-snmp-5.2.1-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"net-snmp-mibs-5.2.1-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"net-snmp-trapd-5.2.1-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"net-snmp-utils-5.2.1-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"perl-NetSNMP-5.2.1-3.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
