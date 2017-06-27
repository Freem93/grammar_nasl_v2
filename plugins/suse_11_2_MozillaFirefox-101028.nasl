#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-3422.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(50464);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/06/13 20:00:37 $");

  script_cve_id("CVE-2010-3170", "CVE-2010-3174", "CVE-2010-3175", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3182", "CVE-2010-3183", "CVE-2010-3765");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-3422)");
  script_summary(english:"Check for the MozillaFirefox-3422 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to version 3.6.12, fixing various
bugs and security issues.

The following security issues were fixed: MFSA 2010-64: Mozilla
developers identified and fixed several memory safety bugs in the
browser engine used in Firefox and other Mozilla-based products. Some
of these bugs showed evidence of memory corruption under certain
circumstances, and we presume that with enough effort at least some of
these could be exploited to run arbitrary code. References

Paul Nickerson, Jesse Ruderman, Olli Pettay, Igor Bukanov and Josh
Soref reported memory safety problems that affected Firefox 3.6 and
Firefox 3.5.

  - Memory safety bugs - Firefox 3.6, Firefox 3.5

  - CVE-2010-3176

Gary Kwong, Martijn Wargers and Siddharth Agarwal reported memory
safety problems that affected Firefox 3.6 only.

  - Memory safety bugs - Firefox 3.6

  - CVE-2010-3175

MFSA 2010-65 / CVE-2010-3179: Security researcher Alexander Miller
reported that passing an excessively long string to document.write
could cause text rendering routines to end up in an inconsistent state
with sections of stack memory being overwritten with the string data.
An attacker could use this flaw to crash a victim's browser and
potentially run arbitrary code on their computer.

MFSA 2010-66 / CVE-2010-3180: Security researcher Sergey Glazunov
reported that it was possible to access the locationbar property of a
window object after it had been closed. Since the closed window's
memory could have been subsequently reused by the system it was
possible that an attempt to access the locationbar property could
result in the execution of attacker-controlled memory.

MFSA 2010-67 / CVE-2010-3183: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative that when
window.__lookupGetter__ is called with no arguments the code assumes
the top JavaScript stack value is a property name. Since there were no
arguments passed into the function, the top value could represent
uninitialized memory or a pointer to a previously freed JavaScript
object. Under such circumstances the value is passed to another
subroutine which calls through the dangling pointer, potentially
executing attacker-controlled memory.

MFSA 2010-68 / CVE-2010-3177: Google security researcher Robert
Swiecki reported that functions used by the Gopher parser to convert
text to HTML tags could be exploited to turn text into executable
JavaScript. If an attacker could create a file or directory on a
Gopher server with the encoded script as part of its name the script
would then run in a victim's browser within the context of the site.

MFSA 2010-69 / CVE-2010-3178: Security researcher Eduardo Vela Nava
reported that if a web page opened a new window and used a javascript:
URL to make a modal call, such as alert(), then subsequently navigated
the page to a different domain, once the modal call returned the
opener of the window could get access to objects in the navigated
window. This is a violation of the same-origin policy and could be
used by an attacker to steal information from another website.

MFSA 2010-70 / CVE-2010-3170: Security researcher Richard Moore
reported that when an SSL certificate was created with a common name
containing a wildcard followed by a partial IP address a valid SSL
connection could be established with a server whose IP address matched
the wildcard range by browsing directly to the IP address. It is
extremely unlikely that such a certificate would be issued by a
Certificate Authority.

MFSA 2010-71 / CVE-2010-3182: Dmitri Gribenko reported that the script
used to launch Mozilla applications on Linux was effectively including
the current working directory in the LD_LIBRARY_PATH environment
variable. If an attacker was able to place into the current working
directory a malicious shared library with the same name as a library
that the bootstrapping script depends on the attacker could have their
library loaded instead of the legitimate library.

MFSA 2010-73 / CVE-2010-3765: Morten Kr&aring;kvik of Telenor SOC
reported an exploit targeting particular versions of Firefox 3.6 on
Windows XP that Telenor found while investigating an intrusion attempt
on a customer network. The underlying vulnerability, however, was
present on both the Firefox 3.5 and Firefox 3.6 development branches
and affected all supported platforms."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=645315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=649492"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Interleaved document.write/appendChild Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/03");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-3.6.12-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-branding-upstream-3.6.12-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-translations-common-3.6.12-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-translations-other-3.6.12-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-js192-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner192-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner192-devel-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner192-gnome-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner192-translations-common-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner192-translations-other-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.12-0.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.12-0.8.1") ) flag++;

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
