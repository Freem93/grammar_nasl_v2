#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1390 and 
# CentOS Errata and Security Advisory 2014:1390 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79179);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2014-3593");
  script_xref(name:"RHSA", value:"2014:1390");

  script_name(english:"CentOS 6 : luci (CESA-2014:1390)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated luci packages that fix one security issue, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Luci is a web-based high availability administration application.

It was discovered that luci used eval() on inputs containing strings
from the cluster configuration file when generating its web pages. An
attacker with privileges to create or edit the cluster configuration
could use this flaw to execute arbitrary code as the luci user on a
host running luci. (CVE-2014-3593)

This issue was discovered by Jan Pokorny of Red Hat.

These updated luci packages also include several bug fixes and
multiple enhancements. Space precludes documenting all of these
changes in this advisory. Users are directed to the Red Hat Enterprise
Linux 6.6 Technical Notes, linked to in the References section, for
information on the most significant of these changes.

All luci users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2014-October/001283.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f173636"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected luci package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:luci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"luci-0.26.0-63.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
