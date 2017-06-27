#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1859 and 
# CentOS Errata and Security Advisory 2014:1859 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79299);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:05:38 $");

  script_cve_id("CVE-2012-5615", "CVE-2014-2494", "CVE-2014-4207", "CVE-2014-4243", "CVE-2014-4258", "CVE-2014-4260", "CVE-2014-4274", "CVE-2014-4287", "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6484", "CVE-2014-6505", "CVE-2014-6507", "CVE-2014-6520", "CVE-2014-6530", "CVE-2014-6551", "CVE-2014-6555", "CVE-2014-6559");
  script_bugtraq_id(68564, 68573, 68579, 68593, 68611, 69732, 70446, 70451, 70455, 70462, 70486, 70487, 70510, 70516, 70517, 70530, 70532, 70550);
  script_osvdb_id(88067, 109156, 109157, 109158, 109160, 109164, 109726, 113252, 113255, 113256, 113257, 113259, 113264, 113265, 113266, 113267, 113269, 113271, 113272);
  script_xref(name:"RHSA", value:"2014:1859");

  script_name(english:"CentOS 5 : mysql55-mysql (CESA-2014:1859)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql55-mysql packages that fix several security issues are
now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

This update fixes several vulnerabilities in the MySQL database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2014-2494, CVE-2014-4207, CVE-2014-4243, CVE-2014-4258,
CVE-2014-4260, CVE-2014-4287, CVE-2014-4274, CVE-2014-6463,
CVE-2014-6464, CVE-2014-6469, CVE-2014-6484, CVE-2014-6505,
CVE-2014-6507, CVE-2014-6520, CVE-2014-6530, CVE-2014-6551,
CVE-2014-6555, CVE-2014-6559)

These updated packages upgrade MySQL to version 5.5.40. Refer to the
MySQL Release Notes listed in the References section for a complete
list of changes.

All MySQL users should upgrade to these updated packages, which
correct these issues. After installing this update, the MySQL server
daemon (mysqld) will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-November/020762.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9996924a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql55-mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql55-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql55-mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql55-mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql55-mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql55-mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql55-mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/18");
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
if (rpm_check(release:"CentOS-5", reference:"mysql55-mysql-5.5.40-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql55-mysql-bench-5.5.40-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql55-mysql-devel-5.5.40-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql55-mysql-libs-5.5.40-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql55-mysql-server-5.5.40-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql55-mysql-test-5.5.40-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
