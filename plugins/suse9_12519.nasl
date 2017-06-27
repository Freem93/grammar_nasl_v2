#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(42048);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2009-1307", "CVE-2009-1311", "CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841", "CVE-2009-2210");

  script_name(english:"SuSE9 Security Update : epiphany (YOU Patch Number 12519)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings the Mozilla SeaMonkey Suite packages to the current
stable release 1.1.17.

Due to the major version update some incompatibilities might appear.

It fixes all currently published security issues, including but not
limited to :

  - Same-origin violations when Adobe Flash loaded via
    view-source: scheme. (MFSA 2009-17 / CVE-2009-1307)

  - POST data sent to wrong site when saving web page with
    embedded frame. (MFSA 2009-21 / CVE-2009-1311)

  - Crashes with evidence of memory corruption
    (rv:1.9.0.11). (MFSA 2009-24 /
    CVE-2009-1392/CVE-2009-1832 / CVE-2009-1833)

  - Arbitrary domain cookie access by local file: resources.
    (MFSA 2009-26 / CVE-2009-1835)

  - SSL tampering via non-200 responses to proxy CONNECT
    requests. (MFSA 2009-27 / CVE-2009-1836)

  - Arbitrary code execution using event listeners attached
    to an element whose owner document is null. (MFSA
    2009-29 / CVE-2009-1838)

  - JavaScript chrome privilege escalation. (MFSA 2009-32 /
    CVE-2009-1841)

  - Crash viewing multipart/alternative message with
    text/enhanced part. (MFSA 2009-33 / CVE-2009-2210)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1307.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1311.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1392.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1832.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1833.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2210.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12519.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 200, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"mozilla-1.8_seamonkey_1.1.17-0.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-devel-1.8_seamonkey_1.1.17-0.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-dom-inspector-1.8_seamonkey_1.1.17-0.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-irc-1.8_seamonkey_1.1.17-0.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-mail-1.8_seamonkey_1.1.17-0.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-venkman-1.8_seamonkey_1.1.17-0.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
