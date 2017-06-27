#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1359 and 
# CentOS Errata and Security Advisory 2011:1359 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56408);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/28 23:58:54 $");

  script_cve_id("CVE-2010-4818", "CVE-2010-4819");
  script_xref(name:"RHSA", value:"2011:1359");

  script_name(english:"CentOS 5 : xorg-x11-server (CESA-2011:1359)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11-server packages that fix multiple security issues are
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

Multiple input sanitization flaws were found in the X.Org GLX (OpenGL
extension to the X Window System) extension. A malicious, authorized
client could use these flaws to crash the X.Org server or,
potentially, execute arbitrary code with root privileges.
(CVE-2010-4818)

An input sanitization flaw was found in the X.Org Render extension. A
malicious, authorized client could use this flaw to leak arbitrary
memory from the X.Org server process, or possibly crash the X.Org
server. (CVE-2010-4819)

Users of xorg-x11-server should upgrade to these updated packages,
which contain backported patches to resolve these issues. All running
X.Org server instances must be restarted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-October/018099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96c847d5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-October/018100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8e7a0d6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvnc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xdmx-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xephyr-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xnest-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xorg-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xvfb-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xvnc-source-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-sdk-1.1.1-48.76.el5_7.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
