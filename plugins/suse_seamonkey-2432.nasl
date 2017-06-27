#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update seamonkey-2432.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27438);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/08/21 14:35:38 $");

  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6500", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504", "CVE-2006-6505", "CVE-2006-6506", "CVE-2006-6507");

  script_name(english:"openSUSE 10 Security Update : seamonkey (seamonkey-2432)");
  script_summary(english:"Check for the seamonkey-2432 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update brings Mozilla SeaMonkey to version 1.0.7.

http://www.mozilla.org/projects/security/known-vulnerabilities.html
for more details.

It includes fixes to the following security problems:
CVE-2006-6497/MFSA2006-68: Crashes with evidence of memory corruption
were fixed in the layout engine. CVE-2006-6498/MFSA2006-68: Crashes
with evidence of memory corruption were fixed in the JavaScript
engine. CVE-2006-6499/MFSA2006-68: Crashes regarding floating point
usage were fixed. CVE-2006-6500/MFSA2006-69: This issue only affects
Windows systems, Linux is not affected. CVE-2006-6501/MFSA2006-70: A
privilege escalation using a watch point was fixed.
CVE-2006-6502/MFSA2006-71: A LiveConnect crash finalizing JS objects
was fixed. CVE-2006-6503/MFSA2006-72: A XSS problem caused by setting
img.src to javascript: URI was fixed. CVE-2006-6504/MFSA2006-73: A
Mozilla SVG Processing Remote Code Execution was fixed.
CVE-2006-6505/MFSA2006-74: Some Mail header processing heap overflows
were fixed. CVE-2006-6506/MFSA2006-75: The RSS Feed-preview referrer
leak was fixed. CVE-2006-6507/MFSA2006-76: A XSS problem using outer
window's Function object was fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-spellchecker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-1.0.7-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-calendar-1.0.7-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-dom-inspector-1.0.7-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-irc-1.0.7-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-mail-1.0.7-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-spellchecker-1.0.7-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-venkman-1.0.7-0.1") ) flag++;

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
