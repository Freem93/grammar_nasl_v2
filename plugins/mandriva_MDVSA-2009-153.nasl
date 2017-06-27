#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:153. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(39872);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:11:05 $");

  script_cve_id("CVE-2007-0062");
  script_xref(name:"MDVSA", value:"2009:153");

  script_name(english:"Mandriva Linux Security Advisory : dhcp (MDVSA-2009:153)");
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
"A vulnerability has been found and corrected in ISC DHCP :

Integer overflow in the ISC dhcpd 3.0.x before 3.0.7 and 3.1.x before
3.1.1; and the DHCP server in EMC VMware Workstation before 5.5.5
Build 56455 and 6.x before 6.0.1 Build 55017, Player before 1.0.5
Build 56455 and Player 2 before 2.0.1 Build 55017, ACE before 1.0.3
Build 54075 and ACE 2 before 2.0.1 Build 55017, and Server before
1.0.4 Build 56528; allows remote attackers to cause a denial of
service (daemon crash) or execute arbitrary code via a malformed DHCP
packet with a large dhcp-max-message-size that triggers a stack-based
buffer overflow, related to servers configured to send many DHCP
options to clients (CVE-2007-0062).

This update provides fixes for this vulnerability."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119,189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.1", reference:"dhcp-client-3.0.7-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"dhcp-common-3.0.7-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"dhcp-devel-3.0.7-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"dhcp-doc-3.0.7-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"dhcp-relay-3.0.7-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"dhcp-server-3.0.7-0.1mdv2008.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
