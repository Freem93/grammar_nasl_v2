#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57150);
  script_version ("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/16 11:00:59 $");

  script_cve_id("CVE-2011-0084", "CVE-2011-2378", "CVE-2011-2980", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 7713)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 3.6.20.

It fixes bugs and security issues. Following security issues were
fixed: Mozilla Foundation Security Advisory 2011-30 - MFSA 2011-30

  - Miscellaneous memory safety hazards Mozilla developers
    and community members identified and fixed several
    memory safety bugs in the browser engine used in Firefox
    3.6 and other Mozilla-based products. Some of these bugs
    showed evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code.

    Gary Kwong, Igor Bukanov, Nils and Bob Clary reported
    memory safety issues which affected Firefox 3.6.
    (CVE-2011-2982)

  - Crash in SVGTextElement.getCharNumAtPosition() Security
    researcher regenrecht reported via TippingPoint's Zero
    Day Initiative that a SVG text manipulation routine
    contained a dangling pointer vulnerability.
    (CVE-2011-0084)

  - Privilege escalation using event handlers Mozilla
    security researcher moz_bug_r_a_4 reported a
    vulnerability in event management code that would permit
    JavaScript to be run in the wrong context, including
    that of a different website or potentially in a
    chrome-privileged context. (CVE-2011-2981)

  - Dangling pointer vulnerability in appendChild Security
    researcher regenrecht reported via TippingPoint's Zero
    Day Initiative that appendChild did not correctly
    account for DOM objects it operated upon and could be
    exploited to dereference an invalid pointer.
    (CVE-2011-2378)

  - Privilege escalation dropping a tab element in content
    area Mozilla security researcher moz_bug_r_a4 reported
    that web content could receive chrome privileges if it
    registered for drop events and a browser tab element was
    dropped into the content area. (CVE-2011-2984)

  - Binary planting vulnerability in ThinkPadSensor::Startup
    Security researcher Mitja Kolsek of Acros Security
    reported that ThinkPadSensor::Startup could potentially
    be exploited to load a malicious DLL into the running
    process. (CVE-2011-2980) (This issue is likely Windows
    only)

  - Private data leakage using RegExp.input Security
    researcher shutdown reported that data from other
    domains could be read when RegExp.input was set.
    (CVE-2011-2983)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0084.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2378.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2980.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2982.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2983.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2984.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7713.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-772");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-3.6.20-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-translations-3.6.20-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-xulrunner192-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-xulrunner192-gnome-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-xulrunner192-translations-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-3.6.20-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-translations-3.6.20-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-xulrunner192-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-xulrunner192-gnome-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-xulrunner192-translations-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.20-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.20-1.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
