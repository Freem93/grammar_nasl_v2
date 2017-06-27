#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-125.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39882);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2933", "CVE-2008-2934");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-125)");
  script_summary(english:"Check for the MozillaFirefox-125 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to version 3.0.1. It fixes various
bugs and also following security problems :

MFSA 2008-34 / CVE-2008-2785: An anonymous researcher, via
TippingPoint's Zero Day Initiative program, reported a vulnerability
in Mozilla CSS reference counting code. The vulnerability was caused
by an insufficiently sized variable being used as a reference counter
for CSS objects. By creating a very large number of references to a
common CSS object, this counter could be overflowed which could cause
a crash when the browser attempts to free the CSS object while still
in use. An attacker could use this crash to run arbitrary code on the
victim's computer

MFSA 2008-35 / CVE-2008-2933: Security researcher Billy Rios reported
that if Firefox is not already running, passing it a command-line URI
with pipe symbols will open multiple tabs. This URI splitting could be
used to launch privileged chrome: URIs from the command-line, a
partial bypass of the fix for MFSA 2005-53 which blocks external
applications from loading such URIs.

This vulnerability could also be used by an attacker to launch a file:
URI from the command line opening a malicious local file which could
exfiltrate data from the local filesystem.

Combined with a vulnerability which allows an attacker to inject code
into a chrome document, the above issue could be used to run arbitrary
code on a victim's computer. Such a chrome injection vulnerability was
reported by Mozilla developers Ben Turner and Dan Veditz who showed
that a XUL based SSL error page was not properly sanitizing inputs and
could be used to run arbitrary code with chrome privileges.

MFSA 2008-36 / CVE-2008-2934: Apple Security Researcher Drew Yao
reported a vulnerability in Mozilla graphics code which handles GIF
rendering in Mac OS X. He demonstrated that a GIF file could be
specially crafted to cause the browser to free an uninitialized
pointer. An attacker could use this vulnerability to crash the browser
and potentially execute arbitrary code on the victim's computer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=407573"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 189);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"MozillaFirefox-3.0.1-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"MozillaFirefox-translations-3.0.1-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-1.9.0.1-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-devel-1.9.0.1-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.1-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-translations-1.9.0.1-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.1-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.1-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.1-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-translations / mozilla-xulrunner190 / etc");
}
