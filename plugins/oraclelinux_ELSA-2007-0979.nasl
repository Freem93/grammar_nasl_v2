#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0979 and 
# Oracle Linux Security Advisory ELSA-2007-0979 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67591);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-3844", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
  script_bugtraq_id(22688, 23668, 24725, 25142, 26132);
  script_osvdb_id(33809, 37994, 37995, 38026, 38033, 38034, 38035, 38043, 38044);
  script_xref(name:"RHSA", value:"2007:0979");

  script_name(english:"Oracle Linux 4 / 5 : firefox (ELSA-2007-0979)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0979 :

Updated firefox packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the way in which Firefox processed certain
malformed web content. A web page containing malicious content could
cause Firefox to crash or potentially execute arbitrary code as the
user running Firefox. (CVE-2007-5338, CVE-2007-5339, CVE-2007-5340)

Several flaws were found in the way in which Firefox displayed
malformed web content. A web page containing specially crafted content
could potentially trick a user into surrendering sensitive
information. (CVE-2007-1095, CVE-2007-3844, CVE-2007-3511,
CVE-2007-5334)

A flaw was found in the Firefox sftp protocol handler. A malicious web
page could access data from a remote sftp site, possibly stealing
sensitive user data. (CVE-2007-5337)

A request-splitting flaw was found in the way in which Firefox
generates a digest authentication request. If a user opened a
specially crafted URL, it was possible to perform cross-site scripting
attacks, web cache poisoning, or other, similar exploits.
(CVE-2007-2292)

All users of Firefox are advised to upgrade to these updated packages,
which contain backported patches that correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-October/000361.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-October/000363.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/23");
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
if (rpm_check(release:"EL4", cpu:"i386", reference:"firefox-1.5.0.12-0.7.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"firefox-1.5.0.12-0.7.el4.0.1")) flag++;

if (rpm_check(release:"EL5", reference:"firefox-1.5.0.12-6.el5.0.1")) flag++;
if (rpm_check(release:"EL5", reference:"firefox-devel-1.5.0.12-6.el5.0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-devel");
}
