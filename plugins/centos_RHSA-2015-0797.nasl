#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0797 and 
# CentOS Errata and Security Advisory 2015:0797 respectively.
#

include("compat.inc");

if (description)
{
  script_id(82714);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/23 14:53:35 $");

  script_cve_id("CVE-2015-0255");
  script_osvdb_id(118221);
  script_xref(name:"RHSA", value:"2015:0797");

  script_name(english:"CentOS 6 / 7 : xorg-x11-server (CESA-2015:0797)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11-server packages that fix one security issue are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

A buffer over-read flaw was found in the way the X.Org server handled
XkbGetGeometry requests. A malicious, authorized client could use this
flaw to disclose portions of the X.Org server memory, or cause the
X.Org server to crash using a specially crafted XkbGetGeometry
request. (CVE-2015-0255)

This issue was discovered by Olivier Fourdan of Red Hat.

All xorg-x11-server users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021059.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35ae251e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021060.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a99d08f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xdmx-1.15.0-26.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xephyr-1.15.0-26.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xnest-1.15.0-26.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xorg-1.15.0-26.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xvfb-1.15.0-26.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-common-1.15.0-26.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-devel-1.15.0-26.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-source-1.15.0-26.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-common-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-devel-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-source-1.15.0-33.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
