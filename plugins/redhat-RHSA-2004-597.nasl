#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:597. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15536);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/28 17:55:17 $");

  script_cve_id("CVE-2004-0381", "CVE-2004-0388", "CVE-2004-0457", "CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837", "CVE-2004-0957");
  script_osvdb_id(6420, 6421, 9015, 10658, 10659, 10660);
  script_xref(name:"RHSA", value:"2004:597");

  script_name(english:"RHEL 2.1 : mysql (RHSA-2004:597)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix various security issues, as well as a
number of bugs, are now available for Red Hat Enterprise Linux 2.1.

MySQL is a multi-user, multi-threaded SQL database server.

A number security issues that affect the mysql server have been
reported :

Oleksandr Byelkin discovered that 'ALTER TABLE ... RENAME' checked the
CREATE/INSERT rights of the old table instead of the new one. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0835 to this issue.

Lukasz Wojtow discovered a buffer overrun in the mysql_real_connect
function. In order to exploit this issue an attacker would need to
force the use of a malicious DNS server (CVE-2004-0836).

Dean Ellis discovered that multiple threads ALTERing the same (or
different) MERGE tables to change the UNION could cause the server to
crash or stall (CVE-2004-0837).

Sergei Golubchik discovered that if a user is granted privileges to a
database with a name containing an underscore ('_'), the user also
gains the ability to grant privileges to other databases with similar
names (CVE-2004-0957).

Additionally, the following minor temporary file vulnerabilities were
discovered :

  - Stan Bubroski and Shaun Colley found a temporary file
    vulnerability in the mysqlbug script (CVE-2004-0381). -
    A temporary file vulnerability was discovered in
    mysqld_multi (CVE-2004-0388). - Jeroen van Wolffelaar
    discovered an temporary file vulnerability in the
    mysqlhotcopy script when using the scp method
    (CVE-2004-0457).

All users of mysql should upgrade to these updated packages, which
resolve these issues and also include fixes for a number of small
bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0381.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0388.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0957.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-597.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql, mysql-devel and / or mysql-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/24");
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
  rhsa = "RHSA-2004:597";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mysql-3.23.58-1.72.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mysql-devel-3.23.58-1.72.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mysql-server-3.23.58-1.72.1")) flag++;

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
