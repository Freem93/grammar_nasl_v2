#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update seamonkey-3138.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75732);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/21 14:15:34 $");

  script_cve_id("CVE-2010-2753", "CVE-2010-2760", "CVE-2010-2762", "CVE-2010-2763", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-2770", "CVE-2010-3131", "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169");

  script_name(english:"openSUSE Security Update : seamonkey (openSUSE-SU-2010:0632-2)");
  script_summary(english:"Check for the seamonkey-3138 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla SeaMonkey 2.0 was updated to version 2.0.8, fixing various
bugs and security issues.

Following security issues were fixed: MFSA 2010-49 / CVE-2010-3169:
Mozilla developers identified and fixed several memory safety bugs in
the browser engine used in Firefox and other Mozilla-based products.
Some of these bugs showed evidence of memory corruption under certain
circumstances, and we presume that with enough effort at least some of
these could be exploited to run arbitrary code.

MFSA 2010-50 / CVE-2010-2765: Security researcher Chris Rohlf of
Matasano Security reported that the implementation of the HTML
frameset element contained an integer overflow vulnerability. The code
responsible for parsing the frameset columns used an 8-byte counter
for the column numbers, so when a very large number of columns was
passed in the counter would overflow. When this counter was
subsequently used to allocate memory for the frameset, the memory
buffer would be too small, potentially resulting in a heap buffer
overflow and execution of attacker-controlled memory.

MFSA 2010-51 / CVE-2010-2767: Security researcher Sergey Glazunov
reported a dangling pointer vulnerability in the implementation of
navigator.plugins in which the navigator object could retain a pointer
to the plugins array even after it had been destroyed. An attacker
could potentially use this issue to crash the browser and run
arbitrary code on a victim's computer.

MFSA 2010-52 / CVE-2010-3131: Security researcher Haifei Li of
FortiGuard Labs reported that Firefox could be used to load a
malicious code library that had been planted on a victim's computer.
Firefox attempts to load dwmapi.dll upon startup as part of its
platform detection, so on systems that don't have this library, such
as Windows XP, Firefox will subsequently attempt to load the library
from the current working directory. An attacker could use this
vulnerability to trick a user into downloading a HTML file and a
malicious copy of dwmapi.dll into the same directory on their computer
and opening the HTML file with Firefox, thus causing the malicious
code to be executed. If the attacker was on the same network as the
victim, the malicious DLL could also be loaded via a UNC path. The
attack also requires that Firefox not currently be running when it is
asked to open the HTML file and accompanying DLL.

As this is a Windows only problem, it does not affect the Linux
version. It is listed for completeness only.

MFSA 2010-53 / CVE-2010-3166: Security researcher wushi of team509
reported a heap buffer overflow in code routines responsible for
transforming text runs. A page could be constructed with a
bidirectional text run which upon reflow could result in an incorrect
length being calculated for the run of text. When this value is
subsequently used to allocate memory for the text too small a buffer
may be created potentially resulting in a buffer overflow and the
execution of attacker controlled memory.

MFSA 2010-54 / CVE-2010-2760: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative that there was a remaining
dangling pointer issue leftover from the fix to CVE-2010-2753. Under
certain circumstances one of the pointers held by a XUL tree selection
could be freed and then later reused, potentially resulting in the
execution of attacker-controlled memory.

MFSA 2010-55 / CVE-2010-3168: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative that XUL <tree> objects could
be manipulated such that the setting of certain properties on the
object would trigger the removal of the tree from the DOM and cause
certain sections of deleted memory to be accessed. In products based
on Gecko version 1.9.2 (Firefox 3.6, Thunderbird 3.1) and newer this
memory has been overwritten by a value that will cause an
unexploitable crash. In products based on Gecko version 1.9.1 (Firefox
3.5, Thunderbird 3.0, and SeaMonkey 2.0) and older an attacker could
potentially use this vulnerability to crash a victim's browser and run
arbitrary code on their computer.

MFSA 2010-56 / CVE-2010-3167: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative that the implementation of XUL
<tree>'s content view contains a dangling pointer vulnerability. One
of the content view's methods for accessing the internal structure of
the tree could be manipulated into removing a node prior to accessing
it, resulting in the accessing of deleted memory. If an attacker can
control the contents of the deleted memory prior to its access they
could use this vulnerability to run arbitrary code on a victim's
machine.

MFSA 2010-57 / CVE-2010-2766: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative that code used to normalize a
document contained a logical flaw that could be leveraged to run
arbitrary code. When the normalization code ran, a static count of the
document's child nodes was used in the traversal, so a page could be
constructed that would remove DOM nodes during this normalization
which could lead to the accessing of a deleted object and potentially
the execution of attacker-controlled memory.

MFSA 2010-58 / CVE-2010-2770: Security researcher Marc Schoenefeld
reported that a specially crafted font could be applied to a document
and cause a crash on Mac systems. The crash showed signs of memory
corruption and presumably could be used by an attacker to execute
arbitrary code on a victim's computer.

This issue probably does not affect the Linux builds and so is listed
for completeness.

MFSA 2010-59 / CVE-2010-2762: Mozilla developer Blake Kaplan reported
that the wrapper class XPCSafeJSObjectWrapper (SJOW), a security
wrapper that allows content-defined objects to be safely accessed by
privileged code, creates scope chains ending in outer objects. Users
of SJOWs which expect the scope chain to end on an inner object may be
handed a chrome privileged object which could be leveraged to run
arbitrary JavaScript with chrome privileges.

Michal Zalewski's recent contributions helped to identify this
architectural weakness.

MFSA 2010-60 / CVE-2010-2763: Mozilla security researcher moz_bug_r_a4
reported that the wrapper class XPCSafeJSObjectWrapper (SJOW) on the
Mozilla 1.9.1 development branch has a logical error in its scripted
function implementation that allows the caller to run the function
within the context of another site. This is a violation of the
same-origin policy and could be used to mount an XSS attack.

MFSA 2010-61 / CVE-2010-2768: Security researchers David Huang and
Collin Jackson of Carnegie Mellon University CyLab (Silicon Valley
campus) reported that the type attribute of an <object> tag can
override the charset of a framed HTML document, even when the document
is included across origins. A page could be constructed containing
such an <object> tag which sets the charset of the framed document to
UTF-7. This could potentially allow an attacker to inject UTF-7
encoded JavaScript into a site, bypassing the site's XSS filters, and
then executing the code using the above technique.

MFSA 2010-62 / CVE-2010-2769: Security researcher Paul Stone reported
that when an HTML selection containing JavaScript is copy-and-pasted
or dropped onto a document with designMode enabled the JavaScript will
be executed within the context of the site where the code was dropped.
A malicious site could leverage this issue in an XSS attack by
persuading a user into taking such an action and in the process
running malicious JavaScript within the context of another site.

MFSA 2010-63 / CVE-2010-2764: Matt Haggard reported that the
statusText property of an XMLHttpRequest object is readable by the
requestor even when the request is made across origins. This status
information reveals the presence of a web server and could be used to
gather information about servers on internal private networks.

This issue was also independently reported to Mozilla by Nicholas
Berthaume"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-09/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637303"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/17");
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

if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-2.0.8-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-dom-inspector-2.0.8-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-irc-2.0.8-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-translations-common-2.0.8-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-translations-other-2.0.8-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-venkman-2.0.8-0.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey");
}
