#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56609);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/06/14 20:27:36 $");

  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2996", "CVE-2011-2999", "CVE-2011-3000");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 7783)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 3.6.23, fixing various bugs and
security issues.

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2011-36)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled,, but are potentially a risk in
    browser or browser-like contexts in those products.

  - Benjamin Smedberg, Bob Clary, and Jesse Ruderman
    reported memory safety problems that affected Firefox
    3.6 and Firefox 6. (CVE-2011-2995)

  - Josh Aas reported a potential crash in the plugin API
    that affected Firefox 3.6 only. (CVE-2011-2996)

  - Mark Kaplan reported a potentially exploitable crash due
    to integer underflow when using a large JavaScript
    RegExp expression. We would also like to thank Mark for
    contributing the fix for this problem. (no CVE yet).
    (MFSA 2011-37)

  - Mozilla developer Boris Zbarsky reported that a frame
    named 'location' could shadow the window.location object
    unless a script in a page grabbed a reference to the
    true object before the frame was created. Because some
    plugins use the value of window.location to determine
    the page origin this could fool the plugin into granting
    the plugin content access to another site or the local
    file system in violation of the Same Origin Policy. This
    flaw allows circumvention of the fix added for MFSA
    2010-10. (CVE-2011-2999). (MFSA 2011-38)

  - Ian Graham of Citrix Online reported that when multiple
    Location headers were present in a redirect response
    Mozilla behavior differed from other browsers: Mozilla
    would use the second Location header while Chrome and
    Internet Explorer would use the first. Two copies of
    this header with different values could be a symptom of
    a CRLF injection attack against a vulnerable server.
    Most commonly it is the Location header itself that is
    vulnerable to the response splitting and therefore the
    copy preferred by Mozilla is more likely to be the
    malicious one. It is possible, however, that the first
    copy was the injected one depending on the nature of the
    server vulnerability. (MFSA 2011-39)

    The Mozilla browser engine has been changed to treat two
    copies of this header with different values as an error
    condition. The same has been done with the headers
    Content-Length and Content-Disposition. (CVE-2011-3000)

  - Mariusz Mlynski reported that if you could convince a
    user to hold down the Enter key--as part of a game or
    test, perhaps--a malicious page could pop up a download
    dialog where the held key would then activate the
    default Open action. For some file types this would be
    merely annoying (the equivalent of a pop-up) but other
    file types have powerful scripting capabilities. And
    this would provide an avenue for an attacker to exploit
    a vulnerability in applications not normally exposed to
    potentially hostile internet content. (MFSA 2011-40)

    Holding enter allows arbitrary code execution due to
    Download Manager. (CVE-2011-2372)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-40.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2372.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2995.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2996.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2999.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3000.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7783.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:3, reference:"MozillaFirefox-3.6.23-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"MozillaFirefox-translations-3.6.23-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner192-1.9.2.23-1.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner192-gnome-1.9.2.23-1.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner192-translations-1.9.2.23-1.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.23-1.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.23-1.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.23-1.6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
