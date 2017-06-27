#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0507 and 
# CentOS Errata and Security Advisory 2011:0507 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53872);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2011-0419");
  script_osvdb_id(73388);
  script_xref(name:"RHSA", value:"2011:0507");

  script_name(english:"CentOS 4 / 5 : apr (CESA-2011:0507)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated apr packages that fix one security issue are now available for
Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Apache Portable Runtime (APR) is a portability library used by the
Apache HTTP Server and other projects. It provides a free library of C
data structures and routines.

It was discovered that the apr_fnmatch() function used an
unconstrained recursion when processing patterns with the '*'
wildcard. An attacker could use this flaw to cause an application
using this function, which also accepted untrusted input as a pattern
for matching (such as an httpd server using the mod_autoindex module),
to exhaust all stack memory or use an excessive amount of CPU time
when performing matching. (CVE-2011-0419)

Red Hat would like to thank Maksymilian Arciemowicz for reporting this
issue.

All apr users should upgrade to these updated packages, which contain
a backported patch to correct this issue. Applications using the apr
library, such as httpd, must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017553.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017556.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected apr packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/12");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"apr-0.9.4-25.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"apr-0.9.4-25.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"apr-devel-0.9.4-25.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"apr-devel-0.9.4-25.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"apr-1.2.7-11.el5_6.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-devel-1.2.7-11.el5_6.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-docs-1.2.7-11.el5_6.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
