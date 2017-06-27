#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-745.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74792);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/21 14:15:32 $");

  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");
  script_osvdb_id(86773, 86774, 86775);

  script_name(english:"openSUSE Security Update : Mozilla Suite (openSUSE-SU-2012:1412-1)");
  script_summary(english:"Check for the openSUSE-2012-745 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox, Thunderbird and XULRunner were updated to 16.0.2.
Mozilla SeaMonkey was updated to 2.13.2.

Tracker bug: bnc#786522

A security issues was fixed :

  - MFSA 2012-90/CVE-2012-4194/CVE-2012-4195/CVE-2012-4196
    (bmo#800666, bmo#793121, bmo#802557) Fixes for Location
    object issues

The update also brings back Obsoletes for libproxy's mozjs plugin for
distributions before 12.2 to avoid crashes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-10/msg00090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=793121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=800666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=802557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786522"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Suite packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/27");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-16.0.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-branding-upstream-16.0.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-buildsymbols-16.0.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debuginfo-16.0.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debugsource-16.0.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-devel-16.0.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-common-16.0.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-other-16.0.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-16.0.2-37.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-buildsymbols-16.0.2-37.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debuginfo-16.0.2-37.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debugsource-16.0.2-37.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-16.0.2-37.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-debuginfo-16.0.2-37.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-common-16.0.2-37.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-other-16.0.2-37.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-1.4.5.+16.0.2-37.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-debuginfo-1.4.5.+16.0.2-37.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-2.13.2-41.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-debuginfo-2.13.2-41.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-debugsource-2.13.2-41.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-dom-inspector-2.13.2-41.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-irc-2.13.2-41.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-translations-common-2.13.2-41.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-translations-other-2.13.2-41.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-venkman-2.13.2-41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-16.0.2-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-16.0.2-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-16.0.2-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-16.0.2-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-16.0.2-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-16.0.2-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-16.0.2-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-16.0.2-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-16.0.2-33.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-16.0.2-33.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-16.0.2-33.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-16.0.2-33.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-16.0.2-33.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-debuginfo-16.0.2-33.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-16.0.2-33.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-16.0.2-33.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.4.5.+16.0.2-33.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.4.5.+16.0.2-33.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-2.13.2-2.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debuginfo-2.13.2-2.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debugsource-2.13.2-2.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-dom-inspector-2.13.2-2.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-irc-2.13.2-2.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-common-2.13.2-2.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-other-2.13.2-2.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-venkman-2.13.2-2.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-16.0.2-2.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-16.0.2-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-branding-upstream-16.0.2-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-buildsymbols-16.0.2-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debuginfo-16.0.2-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debugsource-16.0.2-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-devel-16.0.2-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-common-16.0.2-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-other-16.0.2-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-16.0.2-49.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-buildsymbols-16.0.2-49.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debuginfo-16.0.2-49.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debugsource-16.0.2-49.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-16.0.2-49.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-debuginfo-16.0.2-49.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-common-16.0.2-49.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-other-16.0.2-49.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-1.4.5.+16.0.2-49.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-debuginfo-1.4.5.+16.0.2-49.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-debuginfo-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-2.13.2-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-debuginfo-2.13.2-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-debugsource-2.13.2-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-dom-inspector-2.13.2-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-irc-2.13.2-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-translations-common-2.13.2-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-translations-other-2.13.2-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-venkman-2.13.2-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-buildsymbols-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debuginfo-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debugsource-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-debuginfo-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-32bit-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-32bit-16.0.2-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-16.0.2-2.18.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Suite");
}
