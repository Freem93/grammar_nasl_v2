#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:314. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12430);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:44:43 $");

  script_cve_id("CVE-2003-0901");
  script_bugtraq_id(8741);
  script_osvdb_id(8776, 8777);
  script_xref(name:"RHSA", value:"2003:314");

  script_name(english:"RHEL 2.1 : postgresql (RHSA-2003:314)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PostgreSQL packages that correct a buffer overflow in the
to_ascii routines are now available.

PostgreSQL is an advanced Object-Relational database management system
(DBMS).

Two bugs that can lead to buffer overflows have been found in the
PostgreSQL abstract data type to ASCII conversion routines. A remote
attacker who is able to influence the data passed to the to_ascii
functions may be able to execute arbitrary code in the context of the
PostgreSQL server. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2003-0901 to these issues.

In addition, a bug that can lead to leaks has been found in the string
to timestamp abstract data type conversion routine. If the input
string to the to_timestamp() routine is shorter than what the template
string is expecting, the routine will run off the end of the input
string, resulting in a leak and unstable behaviour.

Users of PostgreSQL are advised to upgrade to these erratum packages,
which contain a backported patch that corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0901.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.postgresql.org/pgsql-bugs/2003-09/msg00014.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-314.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/11/12");
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
  rhsa = "RHSA-2003:314";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-contrib-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-devel-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-docs-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-jdbc-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-libs-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-odbc-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-perl-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-python-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-server-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-tcl-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-test-7.1.3-5.rhel2.1AS")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-tk-7.1.3-5.rhel2.1AS")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
  }
}
