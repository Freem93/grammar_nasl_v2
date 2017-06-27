#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29360);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2007-1362", "CVE-2007-1562", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");

  script_name(english:"SuSE 10 Security Update : MozillaFirefox (ZYPP Patch Number 3756)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to security update version 2.0.0.4

  - Chris Thomas demonstrated that XUL popups opened by web
    content could be placed outside the boundaries of the
    content area. This could be used to spoof or hide parts
    of the browser chrome such as the location bar. (MFSA
    2007-17 / CVE-2007-2871)

  - Mozilla contributor moz_bug_r_a4 demonstrated that the
    addEventListener method could be used to inject script
    into another site in violation of the browser's
    same-origin policy. This could be used to access or
    modify private or valuable information from that other
    site. (MFSA 2007-16 / CVE-2007-2870)

  - Nicolas Derouet reported two problems with cookie
    handling in Mozilla clients. Insufficient length checks
    could be use to exhaust browser memory and so to crash
    the browser or at least slow it done by a large degree.
    (MFSA 2007-14 / CVE-2007-1362)

    The second issue was that the cookie path and name
    values were not checked for the presence of the
    delimiter used for internal cookie storage, and if
    present this confused future interpretation of the
    cookie data. This is not considered to be exploitable.

  - Marcel reported that a malicious web page could perform
    a denial of service attack against the form autocomplete
    feature that would persist from session to session until
    the malicious form data was deleted. Filling a text
    field with millions of characters and submitting the
    form will cause the victim's browser to hang for up to
    several minutes while the form data is read, and this
    will happen the first time autocomplete is triggered
    after every browser restart. (MFSA 2007-13 /
    CVE-2007-2869)

    No harm is done to the user's computer, but the
    frustration caused by the hang could prevent use of
    Firefox if users don't know how to clear the bad state.

  - As part of the Firefox 2.0.0.4 and 1.5.0.12 update
    releases Mozilla developers fixed many bugs to improve
    the stability of the product. Some of these crashes that
    showed evidence of memory corruption under certain
    circumstances and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2007-12 / CVE-2007-2867 / CVE-2007-2868)

    Without further investigation we cannot rule out the
    possibility that for some of these an attacker might be
    able to prepare memory for exploitation through some
    means other than JavaScript, such as large images.

  - Incorrect FTP PASV handling could be used by malicious
    ftp servers to do a rudimentary port scanning of for
    instance internal networks of the computer the browser
    is running on. (MFSA 2007-11 / CVE-2007-1562)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-1362.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-1562.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2868.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2869.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2870.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2871.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 3756.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-2.0.0.4-1.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-translations-2.0.0.4-1.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-2.0.0.4-1.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-translations-2.0.0.4-1.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
