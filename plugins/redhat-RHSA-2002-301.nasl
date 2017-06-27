#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2002:301. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12343);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:44:42 $");

  script_cve_id("CVE-2002-0972", "CVE-2002-1397", "CVE-2002-1398", "CVE-2002-1400", "CVE-2002-1401", "CVE-2002-1402");
  script_xref(name:"RHSA", value:"2002:301");

  script_name(english:"RHEL 2.1 : postgresql (RHSA-2002:301)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PostgreSQL packages are available which correct several minor
security vulnerabilities.

[Updated 06 Feb 2003] Added fixed packages for Advanced Workstation
2.1

PostgreSQL is an advanced Object-Relational database management system
(DBMS). Red Hat Linux Advanced Server 2.1 shipped with PostgreSQL
version 7.1.3 which has several security vulnerabilities.

Buffer overflows in PostgreSQL 7.2 allow attackers to cause a denial
of service and possibly execute arbitrary code via long arguments to
the lpad or rpad functions. CVE-2002-0972

Buffer overflow in the cash_words() function for PostgreSQL 7.2 and
earlier allows local users to cause a denial of service and possibly
execute arbitrary code via a malformed argument. CVE-2002-1397

Buffer overflow in the date parser for PostgreSQL before 7.2.2 allows
attackers to cause a denial of service and possibly execute arbitrary
code via a long date string, referred to as a vulnerability 'in
handling long datetime input.' CVE-2002-1398

Heap-based buffer overflow in the repeat() function for PostgreSQL
before 7.2.2 allows attackers to execute arbitrary code by causing
repeat() to generate a large string. CVE-2002-1400

Buffer overflows in circle_poly, path_encode, and path_add allow
attackers to cause a denial of service and possibly execute arbitrary
code. Note that these issues have been fixed in our packages and in
PostgreSQL CVS, but are not included in PostgreSQL version 7.2.2 or
7.2.3. CVE-2002-1401

Buffer overflows in the TZ and SET TIME ZONE enivronment variables for
PostgreSQL 7.2.1 and earlier allow local users to cause a denial of
service and possibly execute arbitrary code. CVE-2002-1402

Note that these vulnerabilities are only critical on open or shared
systems because connecting to the database is required before the
vulnerabilities can be exploited.

The PostgreSQL Global Development Team has released versions of
PostgreSQL that fix these vulnerabilities, and these fixes have been
isolated and backported into the updated 7.1.3 packages provided with
this errata. All users of Red Hat Linux Advanced Server 2.1 who use
PostgreSQL are advised to install these updated packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0972.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1397.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1398.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1400.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lwn.net/Articles/8445/"
  );
  # http://marc.theaimsgroup.com/?l=postgresql-announce&m=103062536330644
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=postgresql-announce&m=103062536330644"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=102978152712430
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=102978152712430"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=102987306029821
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=102987306029821"
  );
  # http://marc.theaimsgroup.com/?l=postgresql-general&m=102995302604086
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=postgresql-general&m=102995302604086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://online.securityfocus.com/archive/1/288334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://online.securityfocus.com/archive/1/288305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://online.securityfocus.com/archive/1/288036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2002-301.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-tk");
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
  rhsa = "RHSA-2002:301";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-contrib-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-devel-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-docs-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-jdbc-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-libs-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-odbc-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-perl-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-python-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-server-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-tcl-7.1.3-4bp.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"postgresql-tk-7.1.3-4bp.2")) flag++;

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
