#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-745.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39888);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/06/13 19:44:02 $");

  script_cve_id("CVE-2009-1044", "CVE-2009-1169");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-745)");
  script_summary(english:"Check for the MozillaFirefox-745 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Firefox Browser was updated to the 3.0.8 release. It fixes
several security issues :

MFSA 2009-13 / CVE-2009-1044: Security researcher Nils reported via
TippingPoint's Zero Day Initiative that the XUL tree method
_moveToEdgeShift was in some cases triggering garbage collection
routines on objects which were still in use. In such cases, the
browser would crash when attempting to access a previously destroyed
object and this crash could be used by an attacker to run arbitrary
code on a victim's computer. This vulnerability was used by the
reporter to win the 2009 CanSecWest Pwn2Own contest. This
vulnerability does not affect Firefox 2, Thunderbird 2, or released
versions of SeaMonkey.

MFSA 2009-12 / CVE-2009-1169:Security researcher Guido Landi
discovered that a XSL stylesheet could be used to crash the browser
during a XSL transformation. An attacker could potentially use this
crash to run arbitrary code on a victim's computer. This vulnerability
was also previously reported as a stability problem by Ubuntu
community member, Andre. Ubuntu community member Michael Rooney
reported Andre's findings to Mozilla, and Mozilla community member
Martin helped reduce Andre's original testcase and contributed a patch
to fix the vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=488955"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"MozillaFirefox-3.0.8-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"MozillaFirefox-translations-3.0.8-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-1.9.0.8-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-devel-1.9.0.8-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.8-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-translations-1.9.0.8-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.8-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.8-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.8-1.1") ) flag++;

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
