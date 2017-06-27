#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1530 and 
# Oracle Linux Security Advisory ELSA-2009-1530 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67948);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3371", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3377", "CVE-2009-3378", "CVE-2009-3379", "CVE-2009-3380", "CVE-2009-3381", "CVE-2009-3382", "CVE-2009-3383", "CVE-2009-3384");
  script_osvdb_id(59381, 59382, 59383, 59384, 59385, 59386, 59388, 59389, 59390, 59391, 59392, 59393, 59394, 59395, 61091);
  script_xref(name:"RHSA", value:"2009:1530");

  script_name(english:"Oracle Linux 4 / 5 : firefox (ELSA-2009-1530)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1530 :

Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox. nspr provides the
Netscape Portable Runtime (NSPR).

A flaw was found in the way Firefox handles form history. A malicious
web page could steal saved form data by synthesizing input events,
causing the browser to auto-fill form fields (which could then be read
by an attacker). (CVE-2009-3370)

A flaw was found in the way Firefox creates temporary file names for
downloaded files. If a local attacker knows the name of a file Firefox
is going to download, they can replace the contents of that file with
arbitrary contents. (CVE-2009-3274)

A flaw was found in the Firefox Proxy Auto-Configuration (PAC) file
processor. If Firefox loads a malicious PAC file, it could crash
Firefox or, potentially, execute arbitrary code with the privileges of
the user running Firefox. (CVE-2009-3372)

A heap-based buffer overflow flaw was found in the Firefox GIF image
processor. A malicious GIF image could crash Firefox or, potentially,
execute arbitrary code with the privileges of the user running
Firefox. (CVE-2009-3373)

A heap-based buffer overflow flaw was found in the Firefox string to
floating point conversion routines. A web page containing malicious
JavaScript could crash Firefox or, potentially, execute arbitrary code
with the privileges of the user running Firefox. (CVE-2009-1563)

A flaw was found in the way Firefox handles text selection. A
malicious website may be able to read highlighted text in a different
domain (e.g. another website the user is viewing), bypassing the
same-origin policy. (CVE-2009-3375)

A flaw was found in the way Firefox displays a right-to-left override
character when downloading a file. In these cases, the name displayed
in the title bar differs from the name displayed in the dialog body.
An attacker could use this flaw to trick a user into downloading a
file that has a file name or extension that differs from what the user
expected. (CVE-2009-3376)

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2009-3374, CVE-2009-3380, CVE-2009-3382)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.0.15. You can find a link to the
Mozilla advisories in the References section of this errata.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.0.15, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-October/001219.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-October/001220.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/28");
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
if (rpm_check(release:"EL4", reference:"firefox-3.0.15-3.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"nspr-4.7.6-1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"nspr-devel-4.7.6-1.el4_8")) flag++;

if (rpm_check(release:"EL5", reference:"firefox-3.0.15-3.0.1.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"nspr-4.7.6-1.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"nspr-devel-4.7.6-1.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-1.9.0.15-3.0.1.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-devel-1.9.0.15-3.0.1.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-devel-unstable-1.9.0.15-3.0.1.el5_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / nspr / nspr-devel / xulrunner / xulrunner-devel / etc");
}
