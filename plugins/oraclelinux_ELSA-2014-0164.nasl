#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0164 and 
# Oracle Linux Security Advisory ELSA-2014-0164 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72471);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:25:13 $");

  script_cve_id("CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0437");
  script_bugtraq_id(64849, 64877, 64880, 64896, 64898, 64904, 64908, 65298);
  script_osvdb_id(102067, 102068, 102069, 102071, 102074, 102075, 102078, 102713, 102714);
  script_xref(name:"RHSA", value:"2014:0164");

  script_name(english:"Oracle Linux 6 : mysql (ELSA-2014-0164)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0164 :

Updated mysql packages that fix several security issues and one bug
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-February/003966.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"mysql-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-bench-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-devel-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-embedded-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-embedded-devel-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-libs-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-server-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-test-5.1.73-3.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-embedded / etc");
}
