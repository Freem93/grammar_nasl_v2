#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0428 and 
# CentOS Errata and Security Advisory 2011:0428 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53339);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/17 13:39:34 $");

  script_cve_id("CVE-2011-0997");
  script_bugtraq_id(47176);
  script_osvdb_id(71493);
  script_xref(name:"RHSA", value:"2011:0428");

  script_name(english:"CentOS 4 / 5 : dhcp (CESA-2011:0428)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dhcp packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address.

It was discovered that the DHCP client daemon, dhclient, did not
sufficiently sanitize certain options provided in DHCP server replies,
such as the client hostname. A malicious DHCP server could send such
an option with a specially crafted value to a DHCP client. If this
option's value was saved on the client system, and then later
insecurely evaluated by a process that assumes the option is trusted,
it could lead to arbitrary code execution with the privileges of that
process. (CVE-2011-0997)

Red Hat would like to thank Sebastian Krahmer of the SuSE Security
Team for reporting this issue.

All dhclient users should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017280.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ababfc10"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017281.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d07861a2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02d48b67"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017296.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3005baf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdhcp4client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdhcp4client-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"dhclient-3.0.1-67.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"dhclient-3.0.1-67.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"dhcp-3.0.1-67.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"dhcp-3.0.1-67.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"dhcp-devel-3.0.1-67.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"dhcp-devel-3.0.1-67.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"dhclient-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dhcp-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dhcp-devel-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libdhcp4client-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libdhcp4client-devel-3.0.5-23.el5_6.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
