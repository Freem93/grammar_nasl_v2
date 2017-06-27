#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0433 and 
# CentOS Errata and Security Advisory 2011:0433 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53433);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id("CVE-2011-0465");
  script_bugtraq_id(47189);
  script_xref(name:"RHSA", value:"2011:0433");
  script_xref(name:"IAVA", value:"2017-A-0098");

  script_name(english:"CentOS 5 : xorg-x11-server-utils (CESA-2011:0433)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated xorg-x11-server-utils package that fixes one security issue
is now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The xorg-x11-server-utils package contains a collection of utilities
used to modify and query the runtime configuration of the X.Org
server. X.Org is an open source implementation of the X Window System.

A flaw was found in the X.Org X server resource database utility,
xrdb. Certain variables were not properly sanitized during the launch
of a user's graphical session, which could possibly allow a remote
attacker to execute arbitrary code with root privileges, if they were
able to make the display manager execute xrdb with a specially crafted
X client hostname. For example, by configuring the hostname on the
target system via a crafted DHCP reply, or by using the X Display
Manager Control Protocol (XDMCP) to connect to that system from a host
that has a special DNS name. (CVE-2011-0465)

Red Hat would like to thank Matthieu Herrb for reporting this issue.
Upstream acknowledges Sebastian Krahmer of the SuSE Security Team as
the original reporter.

Users of xorg-x11-server-utils should upgrade to this updated package,
which contains a backported patch to resolve this issue. All running
X.Org server instances must be restarted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017321.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?256154de"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017322.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa3b53e0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-utils-7.1-5.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
