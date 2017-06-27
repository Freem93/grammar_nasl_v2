#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0825. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50474);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/04 15:51:48 $");

  script_cve_id("CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3833", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");
  script_bugtraq_id(42598, 42599, 42633, 42646, 43676);
  script_osvdb_id(67378, 67379, 67383, 69000, 69001, 69387, 69390, 69391, 69392, 69393, 69394);
  script_xref(name:"RHSA", value:"2010:0825");

  script_name(english:"RHEL 5 : mysql (RHSA-2010:0825)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

It was found that the MySQL PolyFromWKB() function did not sanity
check Well-Known Binary (WKB) data. A remote, authenticated attacker
could use specially crafted WKB data to crash mysqld. This issue only
caused a temporary denial of service, as mysqld was automatically
restarted after the crash. (CVE-2010-3840)

A flaw was found in the way MySQL processed certain JOIN queries. If a
stored procedure contained JOIN queries, and that procedure was
executed twice in sequence, it could cause an infinite loop, leading
to excessive CPU use (up to 100%). A remote, authenticated attacker
could use this flaw to cause a denial of service. (CVE-2010-3839)

A flaw was found in the way MySQL processed queries that provide a
mixture of numeric and longblob data types to the LEAST or GREATEST
function. A remote, authenticated attacker could use this flaw to
crash mysqld. This issue only caused a temporary denial of service, as
mysqld was automatically restarted after the crash. (CVE-2010-3838)

A flaw was found in the way MySQL processed PREPARE statements
containing both GROUP_CONCAT and the WITH ROLLUP modifier. A remote,
authenticated attacker could use this flaw to crash mysqld. This issue
only caused a temporary denial of service, as mysqld was automatically
restarted after the crash. (CVE-2010-3837)

It was found that MySQL did not properly pre-evaluate LIKE arguments
in view prepare mode. A remote, authenticated attacker could possibly
use this flaw to crash mysqld. (CVE-2010-3836)

A flaw was found in the way MySQL processed statements that assign a
value to a user-defined variable and that also contain a logical value
evaluation. A remote, authenticated attacker could use this flaw to
crash mysqld. This issue only caused a temporary denial of service, as
mysqld was automatically restarted after the crash. (CVE-2010-3835)

A flaw was found in the way MySQL evaluated the arguments of
extreme-value functions, such as LEAST and GREATEST. A remote,
authenticated attacker could use this flaw to crash mysqld. This issue
only caused a temporary denial of service, as mysqld was automatically
restarted after the crash. (CVE-2010-3833)

A flaw was found in the way MySQL processed EXPLAIN statements for
some complex SELECT queries. A remote, authenticated attacker could
use this flaw to crash mysqld. This issue only caused a temporary
denial of service, as mysqld was automatically restarted after the
crash. (CVE-2010-3682)

A flaw was found in the way MySQL processed certain alternating READ
requests provided by HANDLER statements. A remote, authenticated
attacker could use this flaw to provide such requests, causing mysqld
to crash. This issue only caused a temporary denial of service, as
mysqld was automatically restarted after the crash. (CVE-2010-3681)

A flaw was found in the way MySQL processed CREATE TEMPORARY TABLE
statements that define NULL columns when using the InnoDB storage
engine. A remote, authenticated attacker could use this flaw to crash
mysqld. This issue only caused a temporary denial of service, as
mysqld was automatically restarted after the crash. (CVE-2010-3680)

A flaw was found in the way MySQL processed JOIN queries that attempt
to retrieve data from a unique SET column. A remote, authenticated
attacker could use this flaw to crash mysqld. This issue only caused a
temporary denial of service, as mysqld was automatically restarted
after the crash. (CVE-2010-3677)

All MySQL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3677.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3680.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3681.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3682.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3833.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0825.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2010:0825";
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
  if (rpm_check(release:"RHEL5", reference:"mysql-5.0.77-4.el5_5.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-bench-5.0.77-4.el5_5.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-bench-5.0.77-4.el5_5.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-bench-5.0.77-4.el5_5.4")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mysql-devel-5.0.77-4.el5_5.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-server-5.0.77-4.el5_5.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-server-5.0.77-4.el5_5.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-server-5.0.77-4.el5_5.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-test-5.0.77-4.el5_5.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-test-5.0.77-4.el5_5.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-test-5.0.77-4.el5_5.4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-server / mysql-test");
  }
}
