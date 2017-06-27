#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1461 and 
# CentOS Errata and Security Advisory 2012:1461 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62928);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/06/29 00:03:03 $");

  script_cve_id("CVE-2012-4505");
  script_bugtraq_id(55910);
  script_osvdb_id(86567);
  script_xref(name:"RHSA", value:"2012:1461");

  script_name(english:"CentOS 6 : libproxy (CESA-2012:1461)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libproxy packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

libproxy is a library that handles all the details of proxy
configuration.

A buffer overflow flaw was found in the way libproxy handled the
downloading of proxy auto-configuration (PAC) files. A malicious
server hosting a PAC file or a man-in-the-middle attacker could use
this flaw to cause an application using libproxy to crash or,
possibly, execute arbitrary code, if the proxy settings obtained by
libproxy (from the environment or the desktop environment settings)
instructed the use of a PAC proxy configuration. (CVE-2012-4505)

This issue was discovered by the Red Hat Security Response Team.

Users of libproxy should upgrade to these updated packages, which
contain a backported patch to correct this issue. All applications
using libproxy must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-November/018996.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a617906"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libproxy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-mozjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libproxy-webkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libproxy-0.3.0-3.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-bin-0.3.0-3.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-devel-0.3.0-3.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-gnome-0.3.0-3.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-kde-0.3.0-3.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-mozjs-0.3.0-3.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-python-0.3.0-3.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libproxy-webkit-0.3.0-3.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");