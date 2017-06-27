#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-99.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81199);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/11 13:51:33 $");

  script_cve_id("CVE-2014-9625");

  script_name(english:"openSUSE Security Update : vlc (openSUSE-SU-2015:0201-1)");
  script_summary(english:"Check for the openSUSE-2015-99 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"vlc was updated to the current openSUSE Tumbleweed version.

live555 was also updated to the current openSUSE Tumbleweed version as
a dependency.

Security issues fixed :

  - Fix various buffer overflows and null ptr dereferencing
    (boo#914268, CVE-2014-9625).

Other fixes :

  - Enable SSE2 instruction set for x86_64

  - Disable fluidsynth again: the crashes we had earlier are
    still not all fixed. They are less, but less common
    makes it more difficult to debug.

On openSUSE 13.1 :

  - Update to version 2.1.5 :

  + Core: Fix compilation on OS/2.

  + Access: Stability improvements for the QTSound capture
    module.

  + Mac OS X audio output :

  - Fix channel ordering.

  - Increase the buffersize.

  + Decoders :

  - Fix DxVA2 decoding of samples needing more surfaces.

  - Improve MAD resistance to broken mp3 streams.

  - Fix PGS alignment in MKV.

  + Qt Interface: Don't rename mp3 converted files to .raw.

  + Mac OS X Interface :

  - Correctly support video-on-top.

  - Fix video output event propagation on Macs with retina
    displays.

  - Stability improvements when using future VLC releases
    side by side.

  + Streaming: Fix transcode when audio format changes.

  + Updated translations.

  - Update to version 2.1.4 :

  + Demuxers: Fix issue in WMV with multiple compressed
    payload and empty payloads.

  + Video Output: Fix subtitles size rendering on Windows.

  + Mac OS X :

  - Fix DVD playback regression.

  - Fix misleading error message during video playback on OS
    X 10.9.

  - Fix hardware acceleration memleaks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2015-02/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914268"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vlc packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:live555-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/06");
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

if ( rpm_check(release:"SUSE13.1", reference:"libvlc5-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvlc5-debuginfo-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvlccore7-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvlccore7-debuginfo-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"live555-devel-2014.09.22-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-debuginfo-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-debugsource-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-devel-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-gnome-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-gnome-debuginfo-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-noX-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-noX-debuginfo-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-noX-lang-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-qt-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-qt-debuginfo-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvlc5-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvlc5-debuginfo-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvlccore7-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvlccore7-debuginfo-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"live555-devel-2014.09.22-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-debuginfo-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-debugsource-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-devel-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-gnome-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-gnome-debuginfo-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-noX-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-noX-debuginfo-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-noX-lang-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-qt-2.1.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-qt-debuginfo-2.1.5-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "live555-devel / libvlc5 / libvlc5-debuginfo / libvlccore7 / etc");
}
