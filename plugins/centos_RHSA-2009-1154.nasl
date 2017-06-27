#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1154 and 
# CentOS Errata and Security Advisory 2009:1154 respectively.
#

include("compat.inc");

if (description)
{
  script_id(39801);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-0692", "CVE-2009-1893");
  script_bugtraq_id(35668);
  script_osvdb_id(55819, 56464);
  script_xref(name:"RHSA", value:"2009:1154");

  script_name(english:"CentOS 3 : dhcp (CESA-2009:1154)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dhcp packages that fix two security issues are now available
for Red Hat Enterprise Linux 3.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address.

The Mandriva Linux Engineering Team discovered a stack-based buffer
overflow flaw in the ISC DHCP client. If the DHCP client were to
receive a malicious DHCP response, it could crash or execute arbitrary
code with the permissions of the client (root). (CVE-2009-0692)

An insecure temporary file use flaw was discovered in the DHCP
daemon's init script ('/etc/init.d/dhcpd'). A local attacker could use
this flaw to overwrite an arbitrary file with the output of the 'dhcpd
-t' command via a symbolic link attack, if a system administrator
executed the DHCP init script with the 'configtest', 'restart', or
'reload' option. (CVE-2009-1893)

Users of DHCP should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-July/016034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26940df2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-July/016035.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef8e6178"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"dhclient-3.0.1-10.2_EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"dhclient-3.0.1-10.2_EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"dhcp-3.0.1-10.2_EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"dhcp-3.0.1-10.2_EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"dhcp-devel-3.0.1-10.2_EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"dhcp-devel-3.0.1-10.2_EL3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
