#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-465.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74693);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967");
  script_osvdb_id(83995, 83996, 83997, 83998, 83999, 84000, 84001, 84002, 84003, 84004, 84005, 84006, 84007, 84008, 84009, 84010, 84012, 84013);

  script_name(english:"openSUSE Security Update : xulrunner (openSUSE-SU-2012:0924-1)");
  script_summary(english:"Check for the openSUSE-2012-465 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla XULRunner was updated to 14.0.1, fixing bugs and security
issues :

Following security issues were fixed: MFSA 2012-42: Mozilla developers
identified and fixed several memory safety bugs in the browser engine
used in Firefox and other Mozilla-based products. Some of these bugs
showed evidence of memory corruption under certain circumstances, and
we presume that with enough effort at least some of these could be
exploited to run arbitrary code.

CVE-2012-1949: Brian Smith, Gary Kwong, Christian Holler, Jesse
Ruderman, Christoph Diehl, Chris Jones, Brad Lassey, and Kyle Huey
reported memory safety problems and crashes that affect Firefox 13.

CVE-2012-1948: Benoit Jacob, Jesse Ruderman, Christian Holler, and
Bill McCloskey reported memory safety problems and crashes that affect
Firefox ESR 10 and Firefox 13.

MFSA 2012-43 / CVE-2012-1950: Security researcher Mario Gomes
andresearch firm Code Audit Labs reported a mechanism to short-circuit
page loads through drag and drop to the addressbar by canceling the
page load. This causes the address of the previously site entered to
be displayed in the addressbar instead of the currently loaded page.
This could lead to potential phishing attacks on users.

MFSA 2012-44

Google security researcher Abhishek Arya used the Address Sanitizer
tool to uncover four issues: two use-after-free problems, one out of
bounds read bug, and a bad cast. The first use-after-free problem is
caused when an array of nsSMILTimeValueSpec objects is destroyed but
attempts are made to call into objects in this array later. The second
use-after-free problem is in nsDocument::AdoptNode when it adopts into
an empty document and then adopts into another document, emptying the
first one. The heap buffer overflow is in ElementAnimations when data
is read off of end of an array and then pointers are dereferenced. The
bad cast happens when nsTableFrame::InsertFrames is called with frames
in aFrameList that are a mix of row group frames and column group
frames. AppendFrames is not able to handle this mix.

All four of these issues are potentially exploitable. CVE-2012-1951:
Heap-use-after-free in nsSMILTimeValueSpec::IsEventBased
CVE-2012-1954: Heap-use-after-free in nsDocument::AdoptNode
CVE-2012-1953: Out of bounds read in
ElementAnimations::EnsureStyleRuleFor CVE-2012-1952: Bad cast in
nsTableFrame::InsertFrames

MFSA 2012-45 / CVE-2012-1955: Security researcher Mariusz Mlynski
reported an issue with spoofing of the location property. In this
issue, calls to history.forward and history.back are used to navigate
to a site while displaying the previous site in the addressbar but
changing the baseURI to the newer site. This can be used for phishing
by allowing the user input form or other data on the newer, attacking,
site while appearing to be on the older, displayed site. 

MFSA 2012-46 / CVE-2012-1966: Mozilla security researcher moz_bug_r_a4
reported a cross-site scripting (XSS) attack through the context menu
using a data: URL. In this issue, context menu functionality ('View
Image', 'Show only this frame', and 'View background image') are
disallowed in a javascript: URL but allowed in a data: URL, allowing
for XSS. This can lead to arbitrary code execution.

MFSA 2012-47 / CVE-2012-1957: Security researcher Mario Heiderich
reported that JavaScript could be executed in the HTML feed-view using
tag within the RSS . This problem is due to tags not being filtered
out during parsing and can lead to a potential cross-site scripting
(XSS) attack. The flaw existed in a parser utility class and could
affect other parts of the browser or add-ons which rely on that class
to sanitize untrusted input.

MFSA 2012-48 / CVE-2012-1958: Security researcher Arthur Gerkis used
the Address Sanitizer tool to find a use-after-free in
nsGlobalWindow::PageHidden when mFocusedContent is released and
oldFocusedContent is used afterwards. This use-after-free could
possibly allow for remote code execution.

MFSA 2012-49 / CVE-2012-1959: Mozilla developer Bobby Holley found
that same-compartment security wrappers (SCSW) can be bypassed by
passing them to another compartment. Cross-compartment wrappers often
do not go through SCSW,

but have a filtering policy built into them. When an object is wrapped
cross-compartment, the SCSW is stripped off and, when the object is
read read back, it is not known that SCSW was previously present,
resulting in a bypassing of SCSW. This could result in untrusted
content having access to the XBL that implements browser
functionality.

MFSA 2012-50 / CVE-2012-1960: Google developer Tony Payne reported an
out of bounds (OOB) read in QCMS, Mozilla&rsquo;s color management
library. With a carefully crafted color profile portions of a user's
memory could be incorporated into a transformed image and possibly
deciphered.

MFSA 2012-51 / CVE-2012-1961: Bugzilla developer
Fr&eacute;d&eacute;ric Buclin reported that the 'X-Frame-Options
header is ignored when the value is duplicated, for example
X-Frame-Options: SAMEORIGIN, SAMEORIGIN. This duplication occurs for
unknown reasons on some websites and when it occurs results in Mozilla
browsers not being protected against possible clickjacking attacks on
those pages.

MFSA 2012-52 / CVE-2012-1962: Security researcher Bill Keese reported
a memory corruption. This is caused by JSDependentString::undepend
changing a dependent string into a fixed string when there are
additional dependent strings relying on the same base. When the
undepend occurs during conversion, the base data is freed, leaving
other dependent strings with dangling pointers. This can lead to a
potentially exploitable crash.

MFSA 2012-53 / CVE-2012-1963: Security researcher Karthikeyan
Bhargavan of Prosecco at INRIA reported Content Security Policy (CSP)
1.0 implementation errors. CSP violation reports generated by Firefox
and sent to the 'report-uri' location include sensitive data within
the 'blocked-uri' parameter. These include fragment components and
query strings even if the 'blocked-uri' parameter has a different
origin than the protected resource. This can be used to retrieve a
user's OAuth 2.0 access tokens and OpenID credentials by malicious
sites.

MFSA 2012-54 / CVE-2012-1964: Security Researcher Matt McCutchen
reported that a clickjacking attack using the certificate warning
page. A man-in-the-middle (MITM) attacker can use an iframe to display
its own certificate error warning page (about:certerror) with the 'Add
Exception' button of a real warning page from a malicious site. This
can mislead users to adding a certificate exception for a different
site than the perceived one. This can lead to compromised
communications with the user perceived site through the MITM attack
once the certificate exception has been added.

MFSA 2012-55 / CVE-2012-1965: Security researchers Mario Gomes and
Soroush Dalili reported that since Mozilla allows the pseudo-protocol
feed: to prefix any valid URL, it is possible to construct
feed:javascript: URLs that will execute scripts in some contexts. On
some sites it may be possible to use this to evade output filtering
that would otherwise strip javascript: URLs and thus contribute to
cross-site scripting (XSS) problems on these sites.

MFSA 2012-56 / CVE-2012-1967: Mozilla security researcher moz_bug_r_a4
reported a arbitrary code execution attack using a javascript: URL.
The Gecko engine features a JavaScript sandbox utility that allows the
browser or add-ons to safely execute script in the context of a web
page. In certain cases, javascript: URLs are executed in such a
sandbox with insufficient context that can allow those scripts to
escape from the sandbox and run with elevated privilege. This can lead
to arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00054.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=734076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=737559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=746112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=750096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=750620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=750820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=754044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=757376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=758344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=758990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=761014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=761655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=764296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=767778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771583"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xulrunner packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-14.0.1-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-14.0.1-2.32.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xulrunner");
}
