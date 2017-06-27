#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0143 and 
# CentOS Errata and Security Advisory 2012:0143 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57985);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-3026");
  script_osvdb_id(79294);
  script_xref(name:"RHSA", value:"2012:0143");

  script_name(english:"CentOS 5 / 6 : xulrunner (CESA-2012:0143)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xulrunner packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

XULRunner provides the XUL Runtime environment for applications using
the Gecko layout engine.

A heap-based buffer overflow flaw was found in the way XULRunner
handled PNG (Portable Network Graphics) images. A web page containing
a malicious PNG image could cause an application linked against
XULRunner (such as Firefox) to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2011-3026)

All XULRunner users should upgrade to these updated packages, which
correct this issue. After installing the update, applications using
XULRunner must be restarted for the changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018440.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcd0719c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018443.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?899b8272"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xulrunner packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.2.26-2.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.2.26-2.el5_7")) flag++;

if (rpm_check(release:"CentOS-6", reference:"xulrunner-1.9.2.26-2.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-1.9.2.26-2.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
