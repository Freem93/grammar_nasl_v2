#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:003. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13988);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/08/09 10:50:40 $");

  script_cve_id("CVE-2002-1403", "CVE-2003-0066");
  script_xref(name:"MDKSA", value:"2003:003");

  script_name(english:"Mandrake Linux Security Advisory : dhcpcd (MDKSA-2003:003)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was discovered by Simon Kelley in the dhcpcd DHCP
client daemon. dhcpcd has the ability to execute an external script
named dhcpcd-<interface>.exe when an IP address is assigned to that
network interface. The script sources the file
/var/lib/dhcpcd/dhcpcd-<interface>.info which contains shell variables
and DHCP assignment information. The way quotes are handled inside
these assignments is flawed, and a malicious DHCP server can execute
arbitrary shell commands on the vulnerable DHCP client system. This
can also be exploited by an attacker able to spoof DHCP responses.

Mandrake Linux packages contain a sample /etc/dhcpc/dhcpcd.exe file
and encourages all users to upgrade immediately. Please note that when
you do upgrade, you will have to restart the network for the changes
to take proper effect by issuing 'service network restart' as root."
  );
  # http://www.phystech.com/download/dhcdcd_changelog.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.net-security.org/advisory.php?id=1473"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dhcpcd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcpcd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"dhcpcd-1.3.22pl4-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"dhcpcd-1.3.22pl4-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"dhcpcd-1.3.22pl4-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"dhcpcd-1.3.22pl4-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"dhcpcd-1.3.22pl4-1.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
