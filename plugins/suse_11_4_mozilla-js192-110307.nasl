#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update mozilla-js192-4105.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75954);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0061", "CVE-2011-0062");

  script_name(english:"openSUSE Security Update : mozilla-js192 (mozilla-js192-4105)");
  script_summary(english:"Check for the mozilla-js192-4105 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to version 1.9.2.15, fixing various
security issues.

Following security issues were fixed: MFSA 2011-01: Mozilla developers
identified and fixed several memory safety bugs in the browser engine
used in Firefox and other Mozilla-based products. Some of these bugs
showed evidence of memory corruption under certain circumstances, and
we presume that with enough effort at least some of these could be
exploited to run arbitrary code. References

Jesse Ruderman, Igor Bukanov, Olli Pettay, Gary Kwong, Jeff Walden,
Henry Sivonen, Martijn Wargers, David Baron and Marcia Knous reported
memory safety problems that affected Firefox 3.6 and Firefox 3.5.
(CVE-2011-0053)

Igor Bukanov and Gary Kwong reported memory safety problems that
affected Firefox 3.6 only. (CVE-2011-0062)

MFSA 2011-02 / CVE-2011-0051: Security researcher Zach Hoffman
reported that a recursive call to eval() wrapped in a try/catch
statement places the browser into a inconsistent state. Any dialog box
opened in this state is displayed without text and with
non-functioning buttons. Closing the window causes the dialog to
evaluate to true. An attacker could use this issue to force a user
into accepting any dialog, such as one granting elevated privileges to
the page presenting the dialog.

MFSA 2011-03 / CVE-2011-0055: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative that a method used by
JSON.stringify contained a use-after-free error in which a currently
in-use pointer was freed and subsequently dereferenced. This could
lead to arbitrary code execution if an attacker was able to store
malicious code in the freed section of memory.

Mozilla developer Igor Bukanov also independently discovered and
reported this issue two weeks after the initial report was received.

MFSA 2011-04 / CVE-2011-0054: Security researcher Christian Holler
reported that the JavaScript engine's internal memory mapping of
non-local JS variables contained a buffer overflow which could
potentially be used by an attacker to run arbitrary code on a victim's
computer.

MFSA 2011-05 / CVE-2011-0056: Security researcher Christian Holler
reported that the JavaScript engine's internal mapping of string
values contained an error in cases where the number of values being
stored was above 64K. In such cases an offset pointer was manually
moved forwards and backwards to access the larger address space. If an
exception was thrown between the time that the offset pointer was
moved forward and the time it was reset, then the exception object
would be read from an invalid memory address, potentially executing
attacker-controlled memory.

MFSA 2011-06 / CVE-2011-0057: Daniel Kozlowski reported that a
JavaScript Worker could be used to keep a reference to an object that
could be freed during garbage collection. Subsequent calls through
this deleted reference could cause attacker-controlled memory to be
executed on a victim's computer.

MFSA 2011-07 / CVE-2011-0058: Alex Miller reported that when very long
strings were constructed and inserted into an HTML document, the
browser would incorrectly construct the layout objects used to display
the text. Under such conditions an incorrect length would be
calculated for a text run resulting in too small of a memory buffer
being allocated to store the text. This issue could be used by an
attacker to write data past the end of the buffer and execute
malicious code on a victim's computer. This issue affects only Mozilla
browsers on Windows.

MFSA 2011-08 / CVE-2010-1585: Mozilla security developer Roberto Suggi
Liverani reported that ParanoidFragmentSink, a class used to sanitize
potentially unsafe HTML for display, allows javascript: URLs and other
inline JavaScript when the embedding document is a chrome document.
While there are no unsafe uses of this class in any released products,
extension code could have potentially used it in an unsafe manner.

MFSA 2011-09 / CVE-2011-0061: Security researcher Jordi Chancel
reported that a JPEG image could be constructed that would be decoded
incorrectly, causing data to be written past the end of a buffer
created to store the image. An attacker could potentially craft such
an image that would cause malicious code to be stored in memory and
then later executed on a victim's computer.

MFSA 2011-10 / CVE-2011-0059: Adobe security researcher Peleus Uhley
reported that when plugin-initiated requests receive a 307 redirect
response, the plugin is not notified and the request is forwarded to
the new location. This is true even for cross-site redirects, so any
custom headers that were added as part of the initial request would be
forwarded intact across origins. This poses a CSRF risk for web
applications that rely on custom headers only being present in
requests from their own origin."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=667155"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-js192 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/07");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"mozilla-js192-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-js192-debuginfo-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-debuginfo-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-debugsource-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-devel-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-devel-debuginfo-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-gnome-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-gnome-debuginfo-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-translations-common-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-translations-other-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-js192-debuginfo-32bit-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-debuginfo-32bit-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-debuginfo-32bit-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.15-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.15-0.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla XULRunner");
}
