#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1204 and 
# Oracle Linux Security Advisory ELSA-2009-1204 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67907);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 16:53:47 $");

  script_cve_id("CVE-2009-2412");
  script_bugtraq_id(35949);
  script_xref(name:"RHSA", value:"2009:1204");

  script_name(english:"Oracle Linux 4 / 5 : apr / apr-util (ELSA-2009-1204)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1204 :

Updated apr and apr-util packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache Portable Runtime (APR) is a portability library used by the
Apache HTTP Server and other projects. It aims to provide a free
library of C data structures and routines. apr-util is a utility
library used with APR. This library provides additional utility
interfaces for APR; including support for XML parsing, LDAP, database
interfaces, URI parsing, and more.

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the way the Apache Portable Runtime (APR)
manages memory pool and relocatable memory allocations. An attacker
could use these flaws to issue a specially crafted request for memory
allocation, which would lead to a denial of service (application
crash) or, potentially, execute arbitrary code with the privileges of
an application using the APR libraries. (CVE-2009-2412)

All apr and apr-util users should upgrade to these updated packages,
which contain backported patches to correct these issues. Applications
using the APR libraries, such as httpd, must be restarted for this
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-August/001107.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-August/001111.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apr and / or apr-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-util-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/10");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"apr-0.9.4-24.9.el4_8.2")) flag++;
if (rpm_check(release:"EL4", reference:"apr-devel-0.9.4-24.9.el4_8.2")) flag++;
if (rpm_check(release:"EL4", reference:"apr-util-0.9.4-22.el4_8.2")) flag++;
if (rpm_check(release:"EL4", reference:"apr-util-devel-0.9.4-22.el4_8.2")) flag++;

if (rpm_check(release:"EL5", reference:"apr-1.2.7-11.el5_3.1")) flag++;
if (rpm_check(release:"EL5", reference:"apr-devel-1.2.7-11.el5_3.1")) flag++;
if (rpm_check(release:"EL5", reference:"apr-docs-1.2.7-11.el5_3.1")) flag++;
if (rpm_check(release:"EL5", reference:"apr-util-1.2.7-7.el5_3.2")) flag++;
if (rpm_check(release:"EL5", reference:"apr-util-devel-1.2.7-7.el5_3.2")) flag++;
if (rpm_check(release:"EL5", reference:"apr-util-docs-1.2.7-7.el5_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apr / apr-devel / apr-docs / apr-util / apr-util-devel / etc");
}
