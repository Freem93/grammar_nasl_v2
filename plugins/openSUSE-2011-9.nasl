#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2011-9.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74542);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-2372", "CVE-2011-2996", "CVE-2011-2998", "CVE-2011-2999", "CVE-2011-3000", "CVE-2011-3001", "CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3649", "CVE-2011-3650", "CVE-2011-3651", "CVE-2011-3652", "CVE-2011-3653", "CVE-2011-3654", "CVE-2011-3655");

  script_name(english:"openSUSE Security Update : firefox / thunderbird (openSUSE-2011-9)");
  script_summary(english:"Check for the openSUSE-2011-9 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox and Thunderbird were updated to version 8.0 which
fixes several security vulnerabilities :

  - MFSA 2011-52 - Code execution via NoWaiverWrapper
    (CVE-2011-3655)

  - MFSA 2011-51 - Cross-origin image theft on Mac with
    integrated Intel GPU (CVE-2011-3653)

  - MFSA 2011-50 - Cross-origin data theft using canvas and
    Windows D2D (CVE-2011-3649)

  - MFSA 2011-49 - Memory corruption while profiling using
    Firebug (CVE-2011-3650)

  - MFSA 2011-48 - Miscellaneous memory safety hazards
    (rv:8.0) (CVE-2011-3651, CVE-2011-3652, CVE-2011-3654)

  - MFSA 2011-47 - Potential XSS against sites using
    Shift-JIS (CVE-2011-3648)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=707628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728520"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox / thunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-openSUSE");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/18");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-8.0-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-openSUSE-5.0-7.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-8.0-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-8.0-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-8.0-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-8.0-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-8.0-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-8.0-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-8.0-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-8.0-33.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-8.0-33.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-8.0-33.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-8.0-33.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-8.0-33.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-debuginfo-8.0-33.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-8.0-33.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-8.0-33.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-1.99.05-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debuginfo-1.99.05-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debugsource-1.99.05-2.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.3.3+8.0-33.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.3.3+8.0-33.3.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-debuginfo-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-debuginfo-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js192-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js192-debuginfo-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-debuginfo-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debuginfo-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debugsource-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-devel-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-debuginfo-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-debuginfo-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-debuginfo-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-debugsource-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-devel-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-devel-debuginfo-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-gnome-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-gnome-debuginfo-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-translations-common-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-translations-other-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js192-debuginfo-32bit-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-devel-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.12.11-9.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-tools-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-tools-debuginfo-3.12.11-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-debuginfo-32bit-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-debuginfo-32bit-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.24-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-8.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-8.0-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox-branding-openSUSE / MozillaFirefox-debuginfo / etc");
}
