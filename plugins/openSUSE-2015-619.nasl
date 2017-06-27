#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-619.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86238);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/11/08 16:01:24 $");

  script_cve_id("CVE-2015-4476", "CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4502", "CVE-2015-4503", "CVE-2015-4504", "CVE-2015-4505", "CVE-2015-4506", "CVE-2015-4507", "CVE-2015-4508", "CVE-2015-4509", "CVE-2015-4510", "CVE-2015-4511", "CVE-2015-4512", "CVE-2015-4516", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7178", "CVE-2015-7179", "CVE-2015-7180");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2015-619)");
  script_summary(english:"Check for the openSUSE-2015-619 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to Firefox 41.0 (bnc#947003)

Security issues fixed :

  - MFSA 2015-96/CVE-2015-4500/CVE-2015-4501 Miscellaneous
    memory safety hazards

  - MFSA 2015-97/CVE-2015-4503 (bmo#994337) Memory leak in
    mozTCPSocket to servers

  - MFSA 2015-98/CVE-2015-4504 (bmo#1132467) Out of bounds
    read in QCMS library with ICC V4 profile attributes

  - MFSA 2015-99/CVE-2015-4476 (bmo#1162372) (Android only)
    Site attribute spoofing on Android by pasting URL with
    unknown scheme

  - MFSA 2015-100/CVE-2015-4505 (bmo#1177861) (Windows only)
    Arbitrary file manipulation by local user through
    Mozilla updater

  - MFSA 2015-101/CVE-2015-4506 (bmo#1192226) Buffer
    overflow in libvpx while parsing vp9 format video

  - MFSA 2015-102/CVE-2015-4507 (bmo#1192401) Crash when
    using debugger with SavedStacks in JavaScript

  - MFSA 2015-103/CVE-2015-4508 (bmo#1195976) URL spoofing
    in reader mode

  - MFSA 2015-104/CVE-2015-4510 (bmo#1200004) Use-after-free
    with shared workers and IndexedDB

  - MFSA 2015-105/CVE-2015-4511 (bmo#1200148) Buffer
    overflow while decoding WebM video

  - MFSA 2015-106/CVE-2015-4509 (bmo#1198435) Use-after-free
    while manipulating HTML media content

  - MFSA 2015-107/CVE-2015-4512 (bmo#1170390) Out-of-bounds
    read during 2D canvas display on Linux 16-bit color
    depth systems

  - MFSA 2015-108/CVE-2015-4502 (bmo#1105045) Scripted
    proxies can access inner window

  - MFSA 2015-109/CVE-2015-4516 (bmo#904886) JavaScript
    immutable property enforcement can be bypassed

  - MFSA 2015-110/CVE-2015-4519 (bmo#1189814) Dragging and
    dropping images exposes final URL after redirects

  - MFSA 2015-111/CVE-2015-4520 (bmo#1200856, bmo#1200869)
    Errors in the handling of CORS preflight request headers

  - MFSA 2015-112/CVE-2015-4517/CVE-2015-4521/CVE-2015-4522/
    CVE-2015-7174/CVE-2015-7175/CVE-2015-7176/CVE-2015-7177/
    CVE-2015-7180 Vulnerabilities found through code
    inspection

  - MFSA 2015-113/CVE-2015-7178/CVE-2015-7179 (bmo#1189860,
    bmo#1190526) (Windows only) Memory safety errors in
    libGLES in the ANGLE graphics library

  - MFSA 2015-114 (bmo#1167498, bmo#1153672) (Windows only)
    Information disclosure via the High Resolution Time API"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947003"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-41.0-88.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-41.0-88.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-41.0-88.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-41.0-88.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-41.0-88.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-41.0-88.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-41.0-88.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-41.0-88.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-41.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-41.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-41.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-41.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-41.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-41.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-41.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-41.0-44.1") ) flag++;

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
