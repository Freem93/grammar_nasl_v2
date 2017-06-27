#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-5449.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33756);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2933");

  script_name(english:"openSUSE 10 Security Update : MozillaFirefox (MozillaFirefox-5449)");
  script_summary(english:"Check for the MozillaFirefox-5449 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to version 2.0.0.16, which fixes various
bugs and following security issues :

MFSA 2008-34 CVE-2008-2785: An anonymous researcher, via
TippingPoint's Zero Day Initiative program, reported a vulnerability
in Mozilla CSS reference counting code. The vulnerability was caused
by an insufficiently sized variable being used as a reference counter
for CSS objects. By creating a very large number of references to a
common CSS object, this counter could be overflowed which could cause
a crash when the browser attempts to free the CSS object while still
in use. An attacker could use this crash to run arbitrary code on the
victim's computer.

MFSA 2008-35 CVE-2008-2933: Security researcher Billy Rios reported
that if Firefox is not already running, passing it a command-line URI
with pipe symbols will open multiple tabs. This URI splitting could be
used to launch privileged chrome: URIs from the command-line, a
partial bypass of the fix for MFSA 2005-53 which blocks external
applications from loading such URIs. This vulnerability could also be
used by an attacker to launch a file: URI from the command line
opening a malicious local file which could exfiltrate data from the
local filesystem. Combined with a vulnerability which allows an
attacker to inject code into a chrome document, the above issue could
be used to run arbitrary code on a victim's computer. Such a chrome
injection vulnerability was reported by Mozilla developers Ben Turner
and Dan Veditz who showed that a XUL based SSL error page was not
properly sanitizing inputs and could be used to run arbitrary code
with chrome privileges."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"MozillaFirefox-2.0.0.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"MozillaFirefox-translations-2.0.0.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"MozillaFirefox-2.0.0.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"MozillaFirefox-translations-2.0.0.16-0.1") ) flag++;

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
