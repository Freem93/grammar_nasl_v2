#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1268 and 
# CentOS Errata and Security Advisory 2011:1268 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56129);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_xref(name:"RHSA", value:"2011:1268");

  script_name(english:"CentOS 4 / 5 : firefox / xulrunner (CESA-2011:1268)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

The RHSA-2011:1242 Firefox update rendered HTTPS certificates signed
by a certain Certificate Authority (CA) as untrusted, but made an
exception for a select few. This update removes that exception,
rendering every HTTPS certificate signed by that CA as untrusted.
(BZ#735483)

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.22. After installing the update, Firefox
must be restarted for the changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017725.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b748bb0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b486260"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018058.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9633e2cc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018059.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e86b5852"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000304.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6c60766"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000305.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bc55494"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000306.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0cdc3232"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000307.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a50d0e2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or xulrunner packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.22-1.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.22-1.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-3.6.22-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.2.22-1.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.2.22-1.el5_7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
