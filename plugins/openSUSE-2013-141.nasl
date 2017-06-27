#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-141.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74898);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-0765", "CVE-2013-0772", "CVE-2013-0773", "CVE-2013-0774", "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0777", "CVE-2013-0778", "CVE-2013-0779", "CVE-2013-0780", "CVE-2013-0781", "CVE-2013-0782", "CVE-2013-0783");

  script_name(english:"openSUSE Security Update : Mozilla (openSUSE-SU-2013:0323-1)");
  script_summary(english:"Check for the openSUSE-2013-141 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to Firefox 19.0 (bnc#804248)
MozillaThunderbird was updated to Thunderbird 17.0.3 (bnc#804248)
seamonkey was updated to SeaMonkey 2.16 (bnc#804248) xulrunner was
updated to 17.0.3esr (bnc#804248) chmsee was updated to version 2.0.

Changes in MozillaFirefox 19.0 :

  - MFSA 2013-21/CVE-2013-0783/2013-0784 Miscellaneous
    memory safety hazards

  - MFSA 2013-22/CVE-2013-0772 (bmo#801366) Out-of-bounds
    read in image rendering

  - MFSA 2013-23/CVE-2013-0765 (bmo#830614) Wrapped WebIDL
    objects can be wrapped again

  - MFSA 2013-24/CVE-2013-0773 (bmo#809652) Web content
    bypass of COW and SOW security wrappers

  - MFSA 2013-25/CVE-2013-0774 (bmo#827193) Privacy leak in
    JavaScript Workers

  - MFSA 2013-26/CVE-2013-0775 (bmo#831095) Use-after-free
    in nsImageLoadingContent

  - MFSA 2013-27/CVE-2013-0776 (bmo#796475) Phishing on
    HTTPS connection through malicious proxy

  - MFSA 2013-28/CVE-2013-0780/CVE-2013-0782/CVE-2013-0777/
    CVE-2013-0778/CVE-2013-0779/CVE-2013-0781
    Use-after-free, out of bounds read, and buffer overflow
    issues found using Address Sanitizer

  - removed obsolete patches

  - mozilla-webrtc.patch

  - mozilla-gstreamer-803287.patch

  - added patch to fix session restore window order
    (bmo#712763)

  - update to Firefox 18.0.2

  - blocklist and CTP updates

  - fixes in JS engine

  - update to Firefox 18.0.1

  - blocklist updates

  - backed out bmo#677092 (removed patch)

  - fixed problems involving HTTP proxy transactions

  - Fix WebRTC to build on powerpc

Changes in MozillaThunderbird :

  - update to Thunderbird 17.0.3 (bnc#804248)

  - MFSA 2013-21/CVE-2013-0783 Miscellaneous memory safety
    hazards

  - MFSA 2013-24/CVE-2013-0773 (bmo#809652) Web content
    bypass of COW and SOW security wrappers

  - MFSA 2013-25/CVE-2013-0774 (bmo#827193) Privacy leak in
    JavaScript Workers

  - MFSA 2013-26/CVE-2013-0775 (bmo#831095) Use-after-free
    in nsImageLoadingContent

  - MFSA 2013-27/CVE-2013-0776 (bmo#796475) Phishing on
    HTTPS connection through malicious proxy

  - MFSA 2013-28/CVE-2013-0780/CVE-2013-0782 Use-after-free,
    out of bounds read, and buffer overflow issues found
    using Address Sanitizer

  - update Enigmail to 1.5.1

  - The release fixes the regressions found in the past few
    weeks

Changes in seamonkey :

  - update to SeaMonkey 2.16 (bnc#804248)

  - MFSA 2013-21/CVE-2013-0783/2013-0784 Miscellaneous
    memory safety hazards

  - MFSA 2013-22/CVE-2013-0772 (bmo#801366) Out-of-bounds
    read in image rendering

  - MFSA 2013-23/CVE-2013-0765 (bmo#830614) Wrapped WebIDL
    objects can be wrapped again

  - MFSA 2013-24/CVE-2013-0773 (bmo#809652) Web content
    bypass of COW and SOW security wrappers

  - MFSA 2013-25/CVE-2013-0774 (bmo#827193) Privacy leak in
    JavaScript Workers

  - MFSA 2013-26/CVE-2013-0775 (bmo#831095) Use-after-free
    in nsImageLoadingContent

  - MFSA 2013-27/CVE-2013-0776 (bmo#796475) Phishing on
    HTTPS connection through malicious proxy

  - MFSA 2013-28/CVE-2013-0780/CVE-2013-0782/CVE-2013-0777/
    CVE-2013-0778/CVE-2013-0779/CVE-2013-0781
    Use-after-free, out of bounds read, and buffer overflow
    issues found using Address Sanitizer

  - removed obsolete patches

  - mozilla-webrtc.patch

  - mozilla-gstreamer-803287.patch

  - update to SeaMonkey 2.15.2

  - Applications could not be removed from the 'Application
    details' dialog under Preferences, Helper Applications
    (bmo#826771).

  - View / Message Body As could show menu items out of
    context (bmo#831348)

  - update to SeaMonkey 2.15.1

  - backed out bmo#677092 (removed patch)

  - fixed problems involving HTTP proxy transactions

  - backed out restartless language packs as it broke
    multi-locale setup (bmo#677092, bmo#818468)

Changes in xulrunner :

  - update to 17.0.3esr (bnc#804248)

  - MFSA 2013-21/CVE-2013-0783 Miscellaneous memory safety
    hazards

  - MFSA 2013-24/CVE-2013-0773 (bmo#809652) Web content
    bypass of COW and SOW security wrappers

  - MFSA 2013-25/CVE-2013-0774 (bmo#827193) Privacy leak in
    JavaScript Workers

  - MFSA 2013-26/CVE-2013-0775 (bmo#831095) Use-after-free
    in nsImageLoadingContent

  - MFSA 2013-27/CVE-2013-0776 (bmo#796475) Phishing on
    HTTPS connection through malicious proxy

  - MFSA 2013-28/CVE-2013-0780/CVE-2013-0782 Use-after-free,
    out of bounds read, and buffer overflow issues found
    using Address Sanitizer"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00061.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804248"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debugsource");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-19.0-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-19.0-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-19.0-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-19.0-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-19.0-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-19.0-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-19.0-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-19.0-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-17.0.3-33.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-17.0.3-33.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-17.0.3-33.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-17.0.3-33.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-17.0.3-33.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-debuginfo-17.0.3-33.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-17.0.3-33.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-17.0.3-33.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-2.0-2.32.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debuginfo-2.0-2.32.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debugsource-2.0-2.32.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.5.1+17.0.3-33.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.5.1+17.0.3-33.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-2.16-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debuginfo-2.16-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debugsource-2.16-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-dom-inspector-2.16-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-irc-2.16-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-common-2.16-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-other-2.16-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-venkman-2.16-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.3-2.57.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-19.0-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-branding-upstream-19.0-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-buildsymbols-19.0-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debuginfo-19.0-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debugsource-19.0-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-devel-19.0-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-common-19.0-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-other-19.0-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-17.0.3-49.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-buildsymbols-17.0.3-49.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debuginfo-17.0.3-49.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debugsource-17.0.3-49.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-17.0.3-49.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-debuginfo-17.0.3-49.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-common-17.0.3-49.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-other-17.0.3-49.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chmsee-2.0-2.14.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chmsee-debuginfo-2.0-2.14.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chmsee-debugsource-2.0-2.14.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-1.5.1+17.0.3-49.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-debuginfo-1.5.1+17.0.3-49.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-debuginfo-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-2.16-2.34.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-debuginfo-2.16-2.34.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-debugsource-2.16-2.34.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-dom-inspector-2.16-2.34.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-irc-2.16-2.34.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-translations-common-2.16-2.34.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-translations-other-2.16-2.34.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-venkman-2.16-2.34.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-buildsymbols-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debuginfo-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debugsource-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-debuginfo-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-32bit-17.0.3-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.3-2.30.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla");
}
