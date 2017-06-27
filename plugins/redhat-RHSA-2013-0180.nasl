#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0180. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63663);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-2749", "CVE-2012-5611");
  script_bugtraq_id(55120, 56769);
  script_osvdb_id(84755, 88066);
  script_xref(name:"RHSA", value:"2013:0180");

  script_name(english:"RHEL 5 : mysql (RHSA-2013:0180)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

A stack-based buffer overflow flaw was found in the user permission
checking code in MySQL. An authenticated database user could use this
flaw to crash the mysqld daemon or, potentially, execute arbitrary
code with the privileges of the user running the mysqld daemon.
(CVE-2012-5611)

A flaw was found in the way MySQL calculated the key length when
creating a sort order index for certain queries. An authenticated
database user could use this flaw to crash the mysqld daemon.
(CVE-2012-2749)

This update also adds a patch for a potential flaw in the MySQL
password checking function, which could allow an attacker to log into
any MySQL account without knowing the correct password. This problem
(CVE-2012-2122) only affected MySQL packages that use a certain
compiler and C library optimization. It did not affect the mysql
packages in Red Hat Enterprise Linux 5. The patch is being added as a
preventive measure to ensure this problem cannot get exposed in future
revisions of the mysql packages. (BZ#814605)

All MySQL users should upgrade to these updated packages, which
correct these issues. After installing this update, the MySQL server
daemon (mysqld) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2749.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5611.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0180.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0180";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", reference:"mysql-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-bench-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-bench-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-bench-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"mysql-debuginfo-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"mysql-devel-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-server-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-server-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-server-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-test-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-test-5.0.95-5.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-test-5.0.95-5.el5_9")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-debuginfo / mysql-devel / mysql-server / etc");
  }
}
