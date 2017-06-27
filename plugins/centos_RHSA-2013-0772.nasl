#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0772 and 
# CentOS Errata and Security Advisory 2013:0772 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66257);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/11/10 11:40:11 $");

  script_cve_id("CVE-2012-5614", "CVE-2013-1506", "CVE-2013-1521", "CVE-2013-1531", "CVE-2013-1532", "CVE-2013-1544", "CVE-2013-1548", "CVE-2013-1552", "CVE-2013-1555", "CVE-2013-2375", "CVE-2013-2378", "CVE-2013-2389", "CVE-2013-2391", "CVE-2013-2392", "CVE-2013-3808");
  script_bugtraq_id(56776, 59180, 59188, 59196, 59202, 59207, 59209, 59210, 59211, 59223, 59224, 59229, 59237, 59242);
  script_osvdb_id(88065, 92463, 92464, 92465, 92466, 92467, 92470, 92472, 92473, 92474, 92475, 92482, 92483, 92484);
  script_xref(name:"RHSA", value:"2013:0772");

  script_name(english:"CentOS 6 : mysql (CESA-2013:0772)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix several security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

This update fixes several vulnerabilities in the MySQL database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2012-5614, CVE-2013-1506, CVE-2013-1521, CVE-2013-1531,
CVE-2013-1532, CVE-2013-1544, CVE-2013-1548, CVE-2013-1552,
CVE-2013-1555, CVE-2013-2375, CVE-2013-2378, CVE-2013-2389,
CVE-2013-2391, CVE-2013-2392)

These updated packages upgrade MySQL to version 5.1.69. Refer to the
MySQL release notes listed in the References section for a full list
of changes.

All MySQL users should upgrade to these updated packages, which
correct these issues. After installing this update, the MySQL server
daemon (mysqld) will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-April/019707.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8de699d7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"mysql-5.1.69-1.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-bench-5.1.69-1.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-devel-5.1.69-1.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-embedded-5.1.69-1.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-embedded-devel-5.1.69-1.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-libs-5.1.69-1.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-server-5.1.69-1.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-test-5.1.69-1.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
