#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0121 and 
# CentOS Errata and Security Advisory 2013:0121 respectively.
#

include("compat.inc");

if (description)
{
  script_id(63566);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2009-4030", "CVE-2012-4452");
  script_bugtraq_id(55715);
  script_osvdb_id(60665);
  script_xref(name:"RHSA", value:"2013:0121");

  script_name(english:"CentOS 5 : mysql (CESA-2013:0121)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

It was found that the fix for the CVE-2009-4030 issue, a flaw in the
way MySQL checked the paths used as arguments for the DATA DIRECTORY
and INDEX DIRECTORY directives when the 'datadir' option was
configured with a relative path, was incorrectly removed when the
mysql packages in Red Hat Enterprise Linux 5 were updated to version
5.0.95 via RHSA-2012:0127. An authenticated attacker could use this
flaw to bypass the restriction preventing the use of subdirectories of
the MySQL data directory being used as DATA DIRECTORY and INDEX
DIRECTORY paths. This update re-applies the fix for CVE-2009-4030.
(CVE-2012-4452)

Note: If the use of the DATA DIRECTORY and INDEX DIRECTORY directives
were disabled as described in RHSA-2010:0109 (by adding
'symbolic-links=0' to the '[mysqld]' section of the 'my.cnf'
configuration file), users were not vulnerable to this issue.

This issue was discovered by Karel Volny of the Red Hat Quality
Engineering team.

This update also fixes the following bugs :

* Prior to this update, the log file path in the logrotate script did
not behave as expected. As a consequence, the logrotate function
failed to rotate the '/var/log/mysqld.log' file. This update modifies
the logrotate script to allow rotating the mysqld.log file.
(BZ#647223)

* Prior to this update, the mysqld daemon could fail when using the
EXPLAIN flag in prepared statement mode. This update modifies the
underlying code to handle the EXPLAIN flag as expected. (BZ#654000)

* Prior to this update, the mysqld init script could wrongly report
that mysql server startup failed when the server was actually started.
This update modifies the init script to report the status of the
mysqld server as expected. (BZ#703476)

* Prior to this update, the '--enable-profiling' option was by default
disabled. This update enables the profiling feature. (BZ#806365)

All MySQL users are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-January/019160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4a2075e"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-January/000403.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?011d9317"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"mysql-5.0.95-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-bench-5.0.95-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-devel-5.0.95-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-server-5.0.95-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-test-5.0.95-3.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
