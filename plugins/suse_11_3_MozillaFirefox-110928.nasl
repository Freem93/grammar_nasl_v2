#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-5203.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75656);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2996", "CVE-2011-2999", "CVE-2011-3000");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2011:1079-1)");
  script_summary(english:"Check for the MozillaFirefox-5203 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 3.6.23, fixing various bugs and
security issues.

MFSA 2011-36: Mozilla developers identified and fixed several memory
safety bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these bugs showed evidence of memory
corruption under certain circumstances, and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code.

In general these flaws cannot be exploited through email in the
Thunderbird and SeaMonkey products because scripting is disabled,, but
are potentially a risk in browser or browser-like contexts in those
products.

Benjamin Smedberg, Bob Clary, and Jesse Ruderman reported memory
safety problems that affected Firefox 3.6 and Firefox 6.
(CVE-2011-2995)

Josh Aas reported a potential crash in the plugin API that affected
Firefox 3.6 only. (CVE-2011-2996)

MFSA 2011-37: Mark Kaplan reported a potentially exploitable crash due
to integer underflow when using a large JavaScript RegExp expression.
We would also like to thank Mark for contributing the fix for this
problem. (no CVE yet)

MFSA 2011-38: Mozilla developer Boris Zbarsky reported that a frame
named 'location' could shadow the window.location object unless a
script in a page grabbed a reference to the true object before the
frame was created. Because some plugins use the value of
window.location to determine the page origin this could fool the
plugin into granting the plugin content access to another site or the
local file system in violation of the Same Origin Policy. This flaw
allows circumvention of the fix added for MFSA 2010-10.
(CVE-2011-2999)

MFSA 2011-39: Ian Graham of Citrix Online reported that when multiple
Location headers were present in a redirect response Mozilla behavior
differed from other browsers: Mozilla would use the second Location
header while Chrome and Internet Explorer would use the first. Two
copies of this header with different values could be a symptom of a
CRLF injection attack against a vulnerable server. Most commonly it is
the Location header itself that is vulnerable to the response
splitting and therefore the copy preferred by Mozilla is more likely
to be the malicious one. It is possible, however, that the first copy
was the injected one depending on the nature of the server
vulnerability.

The Mozilla browser engine has been changed to treat two copies of
this header with different values as an error condition. The same has
been done with the headers Content-Length and Content-Disposition.
(CVE-2011-3000)

MFSA 2011-40: Mariusz Mlynski reported that if you could convince a
user to hold down the Enter key--as part of a game or test, perhaps--a
malicious page could pop up a download dialog where the held key would
then activate the default Open action. For some file types this would
be merely annoying (the equivalent of a pop-up) but other file types
have powerful scripting capabilities. And this would provide an avenue
for an attacker to exploit a vulnerability in applications not
normally exposed to potentially hostile internet content.

Holding enter allows arbitrary code execution due to Download Manager
(CVE-2011-2372)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-09/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=720264"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-3.6.23-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-branding-upstream-3.6.23-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-translations-common-3.6.23-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-translations-other-3.6.23-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-js192-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-devel-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-gnome-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-translations-common-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-translations-other-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.23-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.23-1.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
