#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2011-101.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74515);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/16 15:47:33 $");

  script_cve_id("CVE-2011-3658", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665", "CVE-2011-3666");

  script_name(english:"openSUSE Security Update : MozillaFirefox / MozillaThunderbird / seamonkey / etc (openSUSE-2011-101)");
  script_summary(english:"Check for the openSUSE-2011-101 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox and Thunderbird version 9 and seamonkey version 2.6
updates fix several security issues :

  - MFSA 2011-53/CVE-2011-3660: Miscellaneous memory safety
    hazards

  - MFSA 2011-54/CVE-2011-3661: Potentially exploitable
    crash in the YARR regular expression library

  - MFSA 2011-55/CVE-2011-3658: nsSVGValue out-of-bounds
    access

  - MFSA 2011-56/CVE-2011-3663: Key detection without
    JavaScript via SVG animation

  - MFSA 2011-58/CVE-2011-3665: Crash scaling video elements
    to extreme sizes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=737533"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / MozillaThunderbird / seamonkey / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSVGValue Out-of-Bounds Access Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-9.0-33.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-9.0-33.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-9.0-33.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-9.0-33.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-9.0-33.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-9.0-33.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-9.0-33.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-1.99.05-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debuginfo-1.99.05-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debugsource-1.99.05-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.3.4+9.0-33.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.3.4+9.0-33.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js192-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js192-debuginfo-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-debuginfo-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-debugsource-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-devel-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-devel-debuginfo-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-gnome-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-gnome-debuginfo-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-translations-common-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-translations-other-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-2.6-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debuginfo-2.6-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debugsource-2.6-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-dom-inspector-2.6-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-irc-2.6-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-common-2.6-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-other-2.6-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-venkman-2.6-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js192-debuginfo-32bit-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-debuginfo-32bit-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-debuginfo-32bit-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.25-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-9.0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-9.0-2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
