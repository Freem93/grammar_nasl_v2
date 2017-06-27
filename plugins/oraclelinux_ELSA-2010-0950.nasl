#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0950 and 
# Oracle Linux Security Advisory ELSA-2010-0950 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68155);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 19:01:49 $");

  script_cve_id("CVE-2010-1623");
  script_bugtraq_id(43673);
  script_osvdb_id(68327);
  script_xref(name:"RHSA", value:"2010:0950");

  script_name(english:"Oracle Linux 4 / 5 / 6 : apr-util (ELSA-2010-0950)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0950 :

Updated apr-util packages that fix one security issue are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Apache Portable Runtime (APR) is a portability library used by the
Apache HTTP Server and other projects. apr-util is a library which
provides additional utility interfaces for APR; including support for
XML parsing, LDAP, database interfaces, URI parsing, and more.

It was found that certain input could cause the apr-util library to
allocate more memory than intended in the apr_brigade_split_line()
function. An attacker able to provide input in small chunks to an
application using the apr-util library (such as httpd) could possibly
use this flaw to trigger high memory consumption. (CVE-2010-1623)

All apr-util users should upgrade to these updated packages, which
contain a backported patch to correct this issue. Applications using
the apr-util library, such as httpd, must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-December/001761.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-December/001762.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001844.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apr-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/09");
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
if (rpm_check(release:"EL4", reference:"apr-util-0.9.4-22.el4_8.3")) flag++;
if (rpm_check(release:"EL4", reference:"apr-util-devel-0.9.4-22.el4_8.3")) flag++;

if (rpm_check(release:"EL5", reference:"apr-util-1.2.7-11.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"apr-util-devel-1.2.7-11.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"apr-util-docs-1.2.7-11.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"apr-util-mysql-1.2.7-11.el5_5.2")) flag++;

if (rpm_check(release:"EL6", reference:"apr-util-1.3.9-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"apr-util-devel-1.3.9-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"apr-util-ldap-1.3.9-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"apr-util-mysql-1.3.9-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"apr-util-odbc-1.3.9-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"apr-util-pgsql-1.3.9-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"apr-util-sqlite-1.3.9-3.el6_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apr-util / apr-util-devel / apr-util-docs / apr-util-ldap / etc");
}
