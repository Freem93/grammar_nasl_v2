#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2002:289. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12340);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/28 17:44:42 $");

  script_cve_id("CVE-2002-1373", "CVE-2002-1374", "CVE-2002-1375", "CVE-2002-1376");
  script_xref(name:"RHSA", value:"2002:289");

  script_name(english:"RHEL 2.1 : mysql (RHSA-2002:289)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages are available for Red Hat Linux Advanced Server 2.1
that fix security vulnerabilities found in the MySQL server.

[Updated 06 Feb 2003] Added fixed packages for Advanced Workstation
2.1

MySQL is a multi-user, multi-threaded SQL database server. While
auditing MySQL, Stefan Esser found security vulnerabilities that can
be used to crash the server or allow MySQL users to gain privileges.

A signed integer vulnerability in the COM_TABLE_DUMP package for MySQL
3.x to 3.23.53a, and 4.x to 4.0.5a, allows remote attackers to cause a
denial of service (crash or hang) in mysqld by causing large negative
integers to be provided to a memcpy call. (CVE-2002-1373)

The COM_CHANGE_USER command in MySQL 3.x to 3.23.53a, and 4.x to
4.0.5a, allows a remote attacker to gain privileges via a brute-force
attack using a one-character password, which causes MySQL to only
compare the provided password against the first character of the real
password. (CVE-2002-1374)

The COM_CHANGE_USER command in MySQL 3.x to 3.23.53a, and 4.x to
4.0.5a, allows remote attackers to execute arbitrary code via a long
response. (CVE-2002-1375)

The MySQL client library (libmysqlclient) in MySQL 3.x to 3.23.53a,
and 4.x to 4.0.5a, does not properly verify length fields for certain
responses in the read_rows or read_one_row routines, which allows a
malicious server to cause a denial of service and possibly execute
arbitrary code. (CVE-2002-1376)

Red Hat Linux Advanced Server 2.1 contains versions of MySQL that are
vulnerable to these issues. All users of MySQL are advised to upgrade
to these errata packages containing MySQL 3.23.54a which is not
vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1373.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1374.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1376.html"
  );
  # http://security.e-matters.de/advisories/042002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b0e0138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2002-289.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql, mysql-devel and / or mysql-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2002:289";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mysql-3.23.54a-3.72")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mysql-devel-3.23.54a-3.72")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mysql-server-3.23.54a-3.72")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-devel / mysql-server");
  }
}
