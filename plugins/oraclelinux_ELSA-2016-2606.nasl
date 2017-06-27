#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2606 and 
# Oracle Linux Security Advisory ELSA-2016-2606 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94725);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/05/19 14:17:02 $");

  script_cve_id("CVE-2016-5423", "CVE-2016-5424");
  script_osvdb_id(142811, 142826);
  script_xref(name:"RHSA", value:"2016:2606");

  script_name(english:"Oracle Linux 7 : postgresql (ELSA-2016-2606)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2606 :

An update for postgresql is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

The following packages have been upgraded to a newer upstream version:
postgresql (9.2.18).

Security Fix(es) :

* A flaw was found in the way PostgreSQL server handled certain SQL
statements containing CASE/WHEN commands. A remote, authenticated
attacker could use a specially crafted SQL statement to cause
PostgreSQL to crash or disclose a few bytes of server memory or
possibly execute arbitrary code. (CVE-2016-5423)

* A flaw was found in the way PostgreSQL client programs handled
database and role names containing newlines, carriage returns, double
quotes, or backslashes. By crafting such an object name, roles with
the CREATEDB or CREATEROLE option could escalate their privileges to
superuser when a superuser next executes maintenance with a vulnerable
client program. (CVE-2016-5424)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Heikki Linnakangas as the original
reporter of CVE-2016-5423; and Nathan Bossart as the original reporter
of CVE-2016-5424.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006491.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-9.2.18-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-contrib-9.2.18-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-devel-9.2.18-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-docs-9.2.18-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-libs-9.2.18-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-plperl-9.2.18-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-plpython-9.2.18-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.18-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-server-9.2.18-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-test-9.2.18-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.18-1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
