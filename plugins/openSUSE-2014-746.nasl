#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-746.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79796);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/18 05:41:18 $");

  script_cve_id("CVE-2014-1587", "CVE-2014-1588", "CVE-2014-1589", "CVE-2014-1590", "CVE-2014-1591", "CVE-2014-1592", "CVE-2014-1593", "CVE-2014-1594");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2014:1581-1)");
  script_summary(english:"Check for the openSUSE-2014-746 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This MozillaFirefox update fixes several security and non security
issues.

Changes in MozillaFirefox :

  - update to Firefox 34.0.5 (bnc#908009)

  - Default search engine changed to Yahoo! for North
    America

  - Default search engine changed to Yandex for Belarusian,
    Kazakh, and Russian locales

  - Improved search bar (en-US only)

  - Firefox Hello real-time communication client

  - Easily switch themes/personas directly in the
    Customizing mode

  - Implementation of HTTP/2 (draft14) and ALPN

  - Disabled SSLv3

  - MFSA 2014-83/CVE-2014-1587/CVE-2014-1588 Miscellaneous
    memory safety hazards

  - MFSA 2014-84/CVE-2014-1589 (bmo#1043787) XBL bindings
    accessible via improper CSS declarations

  - MFSA 2014-85/CVE-2014-1590 (bmo#1087633) XMLHttpRequest
    crashes with some input streams

  - MFSA 2014-86/CVE-2014-1591 (bmo#1069762) CSP leaks
    redirect data via violation reports

  - MFSA 2014-87/CVE-2014-1592 (bmo#1088635) Use-after-free
    during HTML5 parsing

  - MFSA 2014-88/CVE-2014-1593 (bmo#1085175) Buffer overflow
    while parsing media content

  - MFSA 2014-89/CVE-2014-1594 (bmo#1074280) Bad casting
    from the BasicThebesLayer to BasicContainerLayer

  - rebased patches

  - limit linker memory usage for %ix86

  - update to Firefox 33.1

  - Adding DuckDuckGo as a search option (upstream)

  - Forget Button added

  - Enhanced Tiles

  - Privacy tour introduced

  - fix typo in GStreamer Recommends

  - Disable elf-hack for aarch64

  - Enable EGL for aarch64

  - Limit RAM usage during link for %arm

  - Fix _constraints for ARM

  - use proper macros for ARM

  - use '--disable-optimize' not only on 32-bit x86, but on
    32-bit arm too to fix compiling.

  - pass '-Wl,--no-keep-memory' to linker to reduce required
    memory during linking on arm.

  - update to Firefox 33.0.2

  - Fix a startup crash with some combination of hardware
    and drivers 33.0.1

  - Firefox displays a black screen at start-up with certain
    graphics drivers

  - adjusted _constraints for ARM

  - added mozilla-bmo1088588.patch to fix build with EGL
    (bmo#1088588)

  - define /usr/share/myspell as additional dictionary
    location and remove add-plugins.sh finally (bnc#900639)

  - use Firefox default optimization flags instead of -Os

  - specfile cleanup"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908009"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-devel");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/08");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-34.0.5-1.94.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-34.0.5-1.94.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-34.0.5-1.94.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-34.0.5-1.94.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-34.0.5-1.94.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-34.0.5-1.94.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-34.0.5-1.94.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-34.0.5-1.94.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-debuginfo-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-debuginfo-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-4.10.7-1.37.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debuginfo-4.10.7-1.37.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debugsource-4.10.7-1.37.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-devel-4.10.7-1.37.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-debuginfo-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debuginfo-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debugsource-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-devel-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-debuginfo-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-debuginfo-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-32bit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.7-1.37.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.7-1.37.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.17.2-1.63.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-34.0.5-50.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-34.0.5-50.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-34.0.5-50.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-34.0.5-50.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-34.0.5-50.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-34.0.5-50.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-34.0.5-50.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-34.0.5-50.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-debuginfo-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-debuginfo-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-4.10.7-19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-debuginfo-4.10.7-19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-debugsource-4.10.7-19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-devel-4.10.7-19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-debuginfo-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debuginfo-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debugsource-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-devel-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-debuginfo-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-debuginfo-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.7-19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.7-19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.17.2-47.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-34.0.5-5.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-34.0.5-5.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-34.0.5-5.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-34.0.5-5.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-34.0.5-5.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-34.0.5-5.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-34.0.5-5.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-34.0.5-5.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-debuginfo-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-debuginfo-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-4.10.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-debuginfo-4.10.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-debugsource-4.10.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-devel-4.10.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-debuginfo-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debuginfo-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debugsource-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-devel-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-debuginfo-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-debuginfo-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.17.2-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.17.2-4.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
