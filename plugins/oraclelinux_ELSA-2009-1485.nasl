#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1485 and 
# Oracle Linux Security Advisory ELSA-2009-1485 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67937);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 16:53:47 $");

  script_cve_id("CVE-2007-6600", "CVE-2009-3230");
  script_bugtraq_id(36314);
  script_xref(name:"RHSA", value:"2009:1485");

  script_name(english:"Oracle Linux 3 : postgresql (ELSA-2009-1485)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1485 :

Updated postgresql packages that fix a security issue are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced object-relational database management system
(DBMS).

It was discovered that the upstream patch for CVE-2007-6600 included
in the Red Hat Security Advisory RHSA-2008:0039 did not include
protection against misuse of the RESET ROLE and RESET SESSION
AUTHORIZATION commands. An authenticated user could use this flaw to
install malicious code that would later execute with superuser
privileges. (CVE-2009-3230)

All PostgreSQL users should upgrade to these updated packages, which
contain a backported patch to correct this issue. If you are running a
PostgreSQL server, the postgresql service must be restarted for this
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-October/001185.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-contrib-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-contrib-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-devel-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-devel-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-docs-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-docs-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-jdbc-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-jdbc-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-libs-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-libs-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-pl-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-pl-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-python-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-python-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-server-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-server-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-tcl-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-tcl-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-test-7.3.21-2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-test-7.3.21-2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rh-postgresql / rh-postgresql-contrib / rh-postgresql-devel / etc");
}
