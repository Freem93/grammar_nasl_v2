#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0164 and 
# CentOS Errata and Security Advisory 2014:0164 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72491);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0437");
  script_bugtraq_id(64849, 64877, 64880, 64896, 64898, 64904, 64908);
  script_osvdb_id(102067, 102068, 102069, 102071, 102074, 102075, 102078, 102713, 102714);
  script_xref(name:"RHSA", value:"2014:0164");

  script_name(english:"CentOS 6 : mysql (CESA-2014:0164)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix several security issues and one bug
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

This update fixes several vulnerabilities in the MySQL database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2014-0386, CVE-2014-0393, CVE-2014-0401, CVE-2014-0402,
CVE-2014-0412, CVE-2014-0437, CVE-2013-5908)

A buffer overflow flaw was found in the way the MySQL command line
client tool (mysql) processed excessively long version strings. If a
user connected to a malicious MySQL server via the mysql client, the
server could use this flaw to crash the mysql client or, potentially,
execute arbitrary code as the user running the mysql client.
(CVE-2014-0001)

The CVE-2014-0001 issue was discovered by Garth Mollett of the Red Hat
Security Response Team.

This update also fixes the following bug :

* Prior to this update, MySQL did not check whether a MySQL socket was
actually being used by any process before starting the mysqld service.
If a particular mysqld service did not exit cleanly while a socket was
being used by a process, this socket was considered to be still in use
during the next start-up of this service, which resulted in a failure
to start the service up. With this update, if a socket exists but is
not used by any process, it is ignored during the mysqld service
start-up. (BZ#1058719)

These updated packages upgrade MySQL to version 5.1.73. Refer to the
MySQL Release Notes listed in the References section for a complete
list of changes.

All MySQL users should upgrade to these updated packages, which
correct these issues. After installing this update, the MySQL server
daemon (mysqld) will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-February/020155.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?178f163f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/14");
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
if (rpm_check(release:"CentOS-6", reference:"mysql-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-bench-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-devel-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-embedded-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-embedded-devel-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-libs-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-server-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-test-5.1.73-3.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
