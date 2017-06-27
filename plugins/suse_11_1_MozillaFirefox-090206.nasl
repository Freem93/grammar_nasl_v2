#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-509.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40169);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-509)");
  script_summary(english:"Check for the MozillaFirefox-509 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Firefox browser is updated to version 3.0.6 fixing various
security and stability issues.

MFSA 2009-01 / CVE-2009-0352 / CVE-2009-0353: Mozilla developers
identified and fixed several stability bugs in the browser engine used
in Firefox and other Mozilla-based products. Some of these crashes
showed evidence of memory corruption under certain circumstances and
we presume that with enough effort at least some of these could be
exploited to run arbitrary code.

MFSA 2009-02 / CVE-2009-0354: Mozilla security researcher moz_bug_r_a4
reported that a chrome XBL method can be used in conjuction with
window.eval to execute arbitrary JavaScript within the context of
another website, violating the same origin policy. Firefox 2 releases
are not affected.

MFSA 2009-03 / CVE-2009-0355: Mozilla security researcher moz_bug_r_a4
reported that a form input control's type could be changed during the
restoration of a closed tab. An attacker could set an input control's
text value to the path of a local file whose location was known to the
attacker. If the tab was then closed and the victim persuaded to
re-open it, upon restoring the tab the attacker could use this
vulnerability to change the input type to file. Scripts in the page
could then automatically submit the form and steal the contents of the
user's local file.

MFSA 2009-04 / CVE-2009-0356: Mozilla security researcher Georgi
Guninski reported that the fix for an earlier vulnerability reported
by Liu Die Yu using local internet shortcut files to access other
sites (MFSA 2008-47) could be bypassed by redirecting to a privileged
about: URI such as about:plugins. If an attacker could get a victim to
download two files, a malicious HTML file and a .desktop shortcut
file, they could have the HTML document load a privileged chrome
document via the shortcut and both documents would be treated as same
origin. This vulnerability could potentially be used by an attacker to
inject arbitrary code into the chrome document and execute with chrome
privileges. Because this attack has relatively high complexity, the
severity of this issue was determined to be moderate.

MFSA 2009-05 / CVE-2009-0357: Developer and Mozilla community member
Wladimir Palant reported that cookies marked HTTPOnly were readable by
JavaScript via the XMLHttpRequest.getResponseHeader and
XMLHttpRequest.getAllResponseHeaders APIs. This vulnerability bypasses
the security mechanism provided by the HTTPOnly flag which intends to
restrict JavaScript access to document.cookie. The fix prevents the
XMLHttpRequest feature from accessing the Set-Cookie and Set-Cookie2
headers of any response whether or not the HTTPOnly flag was set for
those cookies.

MFSA 2009-06 / CVE-2009-0358: Paul Nel reported that certain HTTP
directives to not cache web pages, Cache-Control: no-store and
Cache-Control: no-cache for HTTPS pages, were being ignored by Firefox
3. On a shared system, applications relying upon these HTTP directives
could potentially expose private data. Another user on the system
could use this vulnerability to view improperly cached pages
containing private data by navigating the browser back."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=470074"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xpcom190");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-3.0.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-branding-upstream-3.0.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-translations-3.0.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-1.9.0.6-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-devel-1.9.0.6-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.6-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-translations-1.9.0.6-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-xpcom190-1.9.0.6-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.6-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.6-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.6-0.1.1") ) flag++;

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
