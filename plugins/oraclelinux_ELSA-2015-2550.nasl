#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2550 and 
# Oracle Linux Security Advisory ELSA-2015-2550 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87231);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/07 21:08:16 $");

  script_cve_id("CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317", "CVE-2015-8710");
  script_osvdb_id(120600, 121175, 130292, 130435, 130535, 130536, 130538, 130539, 130543, 130641, 130642);
  script_xref(name:"RHSA", value:"2015:2550");

  script_name(english:"Oracle Linux 7 : libxml2 (ELSA-2015-2550)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2550 :

Updated libxml2 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libxml2 library is a development toolbox providing the
implementation of various XML standards.

Several denial of service flaws were found in libxml2, a library
providing support for reading, modifying, and writing XML and HTML
files. A remote attacker could provide a specially crafted XML or HTML
file that, when processed by an application using libxml2, would cause
that application to use an excessive amount of CPU, leak potentially
sensitive information, or in certain cases crash the application.
(CVE-2015-1819, CVE-2015-5312, CVE-2015-7497, CVE-2015-7498,
CVE-2015-7499, CVE-2015-7500 CVE-2015-7941, CVE-2015-7942,
CVE-2015-8241, CVE-2015-8242, CVE-2015-8317, BZ#1213957, BZ#1281955)

Red Hat would like to thank the GNOME project for reporting
CVE-2015-7497, CVE-2015-7498, CVE-2015-7499, CVE-2015-7500,
CVE-2015-8241, CVE-2015-8242, and CVE-2015-8317. Upstream acknowledges
Kostya Serebryany of Google as the original reporter of CVE-2015-7497,
CVE-2015-7498, CVE-2015-7499, and CVE-2015-7500; Hugh Davenport as the
original reporter of CVE-2015-8241 and CVE-2015-8242; and Hanno Boeck
as the original reporter of CVE-2015-8317. The CVE-2015-1819 issue was
discovered by Florian Weimer of Red Hat Product Security.

All libxml2 users are advised to upgrade to these updated packages,
which contain a backported patch to correct these issues. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-December/005600.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libxml2-2.9.1-6.0.1.el7_2.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libxml2-devel-2.9.1-6.0.1.el7_2.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libxml2-python-2.9.1-6.0.1.el7_2.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libxml2-static-2.9.1-6.0.1.el7_2.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-devel / libxml2-python / libxml2-static");
}
