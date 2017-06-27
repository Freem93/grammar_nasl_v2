#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-2774.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(47906);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 19:55:04 $");

  script_cve_id("CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1206", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1211", "CVE-2010-1213", "CVE-2010-1214", "CVE-2010-2751", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2010:0430-3)");
  script_summary(english:"Check for the MozillaFirefox-2774 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to the 3.5.11 security release.

It fixes following security bugs: MFSA 2010-34 / CVE-2010-1211:
Mozilla developers identified and fixed several memory safety bugs in
the browser engine used in Firefox and other Mozilla-based products.
Some of these bugs showed evidence of memory corruption under certain
circumstances, and we presume that with enough effort at least some of
these could be exploited to run arbitrary code. Jesse Ruderman, Ehsan
Akhgari, Mats Palmgren, Igor Bukanov, Gary Kwong, Tobias Markus and
Daniel Holbert reported memory safety problems that affected Firefox
3.6 and Firefox 3.5.

MFSA 2010-35 / CVE-2010-1208: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative an error in the DOM attribute
cloning routine where under certain circumstances an event attribute
node can be deleted while another object still contains a reference to
it. This reference could subsequently be accessed, potentially causing
the execution of attacker controlled memory.

MFSA 2010-36 / CVE-2010-1209: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative an error in Mozilla's
implementation of NodeIterator in which a malicious NodeFilter could
be created which would detach nodes from the DOM tree while it was
being traversed. The use of a detached and subsequently deleted node
could result in the execution of attacker-controlled memory.

MFSA 2010-37 / CVE-2010-1214: Security researcher J23 reported via
TippingPoint's Zero Day Initiative an error in the code used to store
the names and values of plugin parameter elements. A malicious page
could embed plugin content containing a very large number of parameter
elements which would cause an overflow in the integer value counting
them. This integer is later used in allocating a memory buffer used to
store the plugin parameters. Under such conditions, too small a buffer
would be created and attacker-controlled data could be written past
the end of the buffer, potentially resulting in code execution.

MFSA 2010-39 / CVE-2010-2752: Security researcher J23 reported via
TippingPoint's Zero Day Initiative that an array class used to store
CSS values contained an integer overflow vulnerability. The 16 bit
integer value used in allocating the size of the array could overflow,
resulting in too small a memory buffer being created. When the array
was later populated with CSS values data would be written past the end
of the buffer potentially resulting in the execution of
attacker-controlled memory.

MFSA 2010-40 / CVE-2010-2753: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative an integer overflow
vulnerability in the implementation of the XUL <tree> element's
selection attribute. When the size of a new selection is sufficiently
large the integer used in calculating the length of the selection can
overflow, resulting in a bogus range being marked selected. When
adjustSelection is then called on the bogus range the range is deleted
leaving dangling references to the ranges which could be used by an
attacker to call into deleted memory and run arbitrary code on a
victim's computer.

MFSA 2010-41 / CVE-2010-1205: OUSPG researcher Aki Helin reported a
buffer overflow in Mozilla graphics code which consumes image data
processed by libpng. A malformed PNG file could be created which would
cause libpng to incorrectly report the size of the image to downstream
consumers. When the dimensions of such images are underreported, the
Mozilla code responsible for displaying the graphic will allocate too
small a memory buffer to contain the image data and will wind up
writing data past the end of the buffer. This could result in the
execution of attacker-controlled memory.

MFSA 2010-42 / CVE-2010-1213: Security researcher Yosuke Hasegawa
reported that the Web Worker method importScripts can read and parse
resources from other domains even when the content is not valid
JavaScript. This is a violation of the same-origin policy and could be
used by an attacker to steal information from other sites.

MFSA 2010-45 / CVE-2010-1206: Google security researcher Michal
Zalewski reported two methods for spoofing the contents of the
location bar. The first method works by opening a new window
containing a resource that responds with an HTTP 204 (no content) and
then using the reference to the new window to insert HTML content into
the blank document. The second location bar spoofing method does not
require that the resource opened in a new window respond with 204, as
long as the opener calls window.stop() before the document is loaded.
In either case a user could be mislead as to the correct location of
the document they are currently viewing.

MFSA 2010-45 / CVE-2010-2751: Security researcher Jordi Chancel
reported that the location bar could be spoofed to look like a secure
page when the current document was served via plaintext. The
vulnerability is triggered by a server by first redirecting a request
for a plaintext resource to another resource behind a valid SSL/TLS
certificate. A second request made to the original plaintext resource
which is responded to not with a redirect but with JavaScript
containing history.back() and history.forward() will result in the
plaintext resource being displayed with valid SSL/TLS badging in the
location bar. References

MFSA 2010-46 / CVE-2010-0654: Google security researcher Chris Evans
reported that data can be read across domains by injecting bogus CSS
selectors into a target site and then retrieving the data using
JavaScript APIs. If an attacker can inject opening and closing
portions of a CSS selector into points A and B of a target page, then
the region between the two injection points becomes readable to
JavaScript through, for example, the getComputedStyle() API.

MFSA 2010-47 / CVE-2010-2754: Security researcher Soroush Dalili
reported that potentially sensitive URL parameters could be leaked
across domains upon script errors when the script filename and line
number is included in the error message."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-07/msg00052.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=622506"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xpcom191");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-3.5.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-branding-upstream-3.5.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-translations-common-3.5.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-translations-other-3.5.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner191-1.9.1.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner191-devel-1.9.1.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner191-translations-common-1.9.1.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner191-translations-other-1.9.1.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-xpcom191-1.9.1.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.11-0.1.1") ) flag++;

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
