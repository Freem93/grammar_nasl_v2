#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:1036 and 
# Oracle Linux Security Advisory ELSA-2008-1036 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67777);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5505", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
  script_bugtraq_id(32882);
  script_osvdb_id(51284, 51285, 51286, 51287, 51288, 51289, 51290, 51291, 51292, 51293, 51294, 51295, 51296, 51297);
  script_xref(name:"RHSA", value:"2008:1036");

  script_name(english:"Oracle Linux 4 / 5 : firefox (ELSA-2008-1036)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:1036 :

An updated firefox package that fixes various security issues is now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code as the user running Firefox.
(CVE-2008-5500, CVE-2008-5501, CVE-2008-5502, CVE-2008-5511,
CVE-2008-5512, CVE-2008-5513)

Several flaws were found in the way malformed content was processed. A
website containing specially crafted content could potentially trick a
Firefox user into surrendering sensitive information. (CVE-2008-5506,
CVE-2008-5507)

A flaw was found in the way Firefox stored attributes in XML User
Interface Language (XUL) elements. A website could use this flaw to
track users across browser sessions, even if users did not allow the
site to store cookies in the victim's browser. (CVE-2008-5505)

A flaw was found in the way malformed URLs were processed by Firefox.
This flaw could prevent various URL sanitization mechanisms from
properly parsing a malicious URL. (CVE-2008-5508)

A flaw was found in Firefox's CSS parser. A malicious web page could
inject NULL characters into a CSS input string, possibly bypassing an
application's script sanitization routines. (CVE-2008-5510)

For technical details regarding these flaws, please see the Mozilla
security advisories for Firefox 3.0.5. You can find a link to the
Mozilla advisories in the References section.

Note: after the errata packages are installed, Firefox must be
restarted for the update to take effect.

All firefox users should upgrade to these updated packages, which
contain backported patches that correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-December/000839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-February/000875.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/18");
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
if (rpm_check(release:"EL4", reference:"firefox-3.0.5-1.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"nspr-4.7.3-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"nspr-devel-4.7.3-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"nss-3.12.2.0-1.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"nss-devel-3.12.2.0-1.0.1.el4")) flag++;

if (rpm_check(release:"EL5", reference:"firefox-3.0.5-1.0.1.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"nspr-4.7.3-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"nspr-devel-4.7.3-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"nss-3.12.2.0-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"nss-devel-3.12.2.0-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"nss-pkcs11-devel-3.12.2.0-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"nss-tools-3.12.2.0-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-1.9.0.5-1.0.1.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-devel-1.9.0.5-1.0.1.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-devel-unstable-1.9.0.5-1.0.1.el5_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / nspr / nspr-devel / nss / nss-devel / nss-pkcs11-devel / etc");
}
