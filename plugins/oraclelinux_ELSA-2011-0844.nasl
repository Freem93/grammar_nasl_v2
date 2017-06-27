#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0844 and 
# Oracle Linux Security Advisory ELSA-2011-0844 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68284);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/06 16:53:48 $");

  script_cve_id("CVE-2011-0419", "CVE-2011-1928");
  script_bugtraq_id(47929);
  script_osvdb_id(73383);
  script_xref(name:"RHSA", value:"2011:0844");

  script_name(english:"Oracle Linux 4 / 5 / 6 : apr (ELSA-2011-0844)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0844 :

Updated apr packages that fix one security issue are now available for
Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Apache Portable Runtime (APR) is a portability library used by the
Apache HTTP Server and other projects. It provides a free library of C
data structures and routines.

The fix for CVE-2011-0419 (released via RHSA-2011:0507) introduced an
infinite loop flaw in the apr_fnmatch() function when the
APR_FNM_PATHNAME matching flag was used. A remote attacker could
possibly use this flaw to cause a denial of service on an application
using the apr_fnmatch() function. (CVE-2011-1928)

Note: This problem affected httpd configurations using the 'Location'
directive with wildcard URLs. The denial of service could have been
triggered during normal operation; it did not specifically require a
malicious HTTP request.

This update also addresses additional problems introduced by the
rewrite of the apr_fnmatch() function, which was necessary to address
the CVE-2011-0419 flaw.

All apr users should upgrade to these updated packages, which contain
a backported patch to correct this issue. Applications using the apr
library, such as httpd, must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-June/002168.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-May/002153.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-May/002157.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected apr packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apr-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/02");
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
if (rpm_check(release:"EL4", reference:"apr-0.9.4-26.el4")) flag++;
if (rpm_check(release:"EL4", reference:"apr-devel-0.9.4-26.el4")) flag++;

if (rpm_check(release:"EL5", reference:"apr-1.2.7-11.el5_6.5")) flag++;
if (rpm_check(release:"EL5", reference:"apr-devel-1.2.7-11.el5_6.5")) flag++;
if (rpm_check(release:"EL5", reference:"apr-docs-1.2.7-11.el5_6.5")) flag++;

if (rpm_check(release:"EL6", reference:"apr-1.3.9-3.el6_1.2")) flag++;
if (rpm_check(release:"EL6", reference:"apr-devel-1.3.9-3.el6_1.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apr / apr-devel / apr-docs");
}
