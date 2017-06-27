#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0950 and 
# CentOS Errata and Security Advisory 2010:0950 respectively.
#

include("compat.inc");

if (description)
{
  script_id(51776);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2010-1623");
  script_bugtraq_id(43673);
  script_osvdb_id(68327);
  script_xref(name:"RHSA", value:"2010:0950");

  script_name(english:"CentOS 4 : apr-util (CESA-2010:0950)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated apr-util packages that fix one security issue are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Apache Portable Runtime (APR) is a portability library used by the
Apache HTTP Server and other projects. apr-util is a library which
provides additional utility interfaces for APR; including support for
XML parsing, LDAP, database interfaces, URI parsing, and more.

It was found that certain input could cause the apr-util library to
allocate more memory than intended in the apr_brigade_split_line()
function. An attacker able to provide input in small chunks to an
application using the apr-util library (such as httpd) could possibly
use this flaw to trigger high memory consumption. (CVE-2010-1623)

All apr-util users should upgrade to these updated packages, which
contain a backported patch to correct this issue. Applications using
the apr-util library, such as httpd, must be restarted for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017225.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3efc91ad"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017226.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b95cf5c0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apr-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"apr-util-0.9.4-22.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"apr-util-0.9.4-22.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"apr-util-devel-0.9.4-22.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"apr-util-devel-0.9.4-22.el4_8.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
