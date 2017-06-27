#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0197 and 
# Oracle Linux Security Advisory ELSA-2011-0197 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68193);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 19:01:50 $");

  script_cve_id("CVE-2010-4015");
  script_bugtraq_id(46084);
  script_osvdb_id(70740);
  script_xref(name:"RHSA", value:"2011:0197");

  script_name(english:"Oracle Linux 4 / 5 / 6 : postgresql (ELSA-2011-0197)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0197 :

Updated postgresql packages that fix one security issue are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

A stack-based buffer overflow flaw was found in the way PostgreSQL
processed certain tokens from a SQL query when the intarray module was
enabled on a particular database. An authenticated database user
running a specially crafted SQL query could use this flaw to cause a
temporary denial of service (postgres daemon crash) or, potentially,
execute arbitrary code with the privileges of the database server.
(CVE-2010-4015)

Red Hat would like to thank Geoff Keating of the Apple Product
Security team for reporting this issue.

For Red Hat Enterprise Linux 4, the updated postgresql packages
contain a backported patch for this issue; there are no other changes.

For Red Hat Enterprise Linux 5, the updated postgresql packages
upgrade PostgreSQL to version 8.1.23, and contain a backported patch
for this issue. Refer to the PostgreSQL Release Notes for a full list
of changes :

http://www.postgresql.org/docs/8.1/static/release.html

For Red Hat Enterprise Linux 6, the updated postgresql packages
upgrade PostgreSQL to version 8.4.7, which includes a fix for this
issue. Refer to the PostgreSQL Release Notes for a full list of
changes :

http://www.postgresql.org/docs/8.4/static/release.html

All PostgreSQL users are advised to upgrade to these updated packages,
which correct this issue. If the postgresql service is running, it
will be automatically restarted after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001812.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001874.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-contrib-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-contrib-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-devel-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-devel-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-docs-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-docs-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-jdbc-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-jdbc-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-libs-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-libs-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-pl-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-pl-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-python-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-python-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-server-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-server-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-tcl-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-tcl-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-test-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-test-7.4.30-1.el4_8.2")) flag++;

if (rpm_check(release:"EL5", reference:"postgresql-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-contrib-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-devel-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-docs-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-libs-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-pl-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-python-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-server-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-tcl-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-test-8.1.23-1.el5_6.1")) flag++;

if (rpm_check(release:"EL6", reference:"postgresql-8.4.7-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-contrib-8.4.7-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-devel-8.4.7-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-docs-8.4.7-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-libs-8.4.7-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-plperl-8.4.7-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-plpython-8.4.7-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-pltcl-8.4.7-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-server-8.4.7-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-test-8.4.7-1.el6_0.1")) flag++;


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
