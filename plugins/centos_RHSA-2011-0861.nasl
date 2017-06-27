#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0861 and 
# CentOS Errata and Security Advisory 2011:0861 respectively.
#

include("compat.inc");

if (description)
{
  script_id(55835);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2011-1752");
  script_bugtraq_id(48091);
  script_osvdb_id(73246);
  script_xref(name:"RHSA", value:"2011:0861");

  script_name(english:"CentOS 4 : subversion (CESA-2011:0861)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated subversion packages that fix one security issue are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module processed requests submitted against the URL of a baselined
resource. A malicious, remote user could use this flaw to cause the
httpd process serving the request to crash. (CVE-2011-1752)

Red Hat would like to thank the Apache Subversion project for
reporting this issue. Upstream acknowledges Joe Schaefer of the Apache
Software Foundation as the original reporter.

All Subversion users should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, you must restart the httpd daemon, if you are using
mod_dav_svn, for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017675.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7cfbe419"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017676.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dc5e02b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/15");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mod_dav_svn-1.1.4-4.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mod_dav_svn-1.1.4-4.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"subversion-1.1.4-4.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"subversion-1.1.4-4.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"subversion-devel-1.1.4-4.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"subversion-devel-1.1.4-4.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"subversion-perl-1.1.4-4.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"subversion-perl-1.1.4-4.el4_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
