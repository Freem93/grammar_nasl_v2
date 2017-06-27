#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-178.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75273);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-3565");

  script_name(english:"openSUSE Security Update : vlc (openSUSE-SU-2014:0315-1)");
  script_summary(english:"Check for the openSUSE-2014-178 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"VLC was updated to version 2.1.3 (bnc#864422) :

  + Core :

  - Fix broken behaviour with SOCKSv5 proxies

  - Fix integer overflow on error when using vlc_readdir

  + Access :

  - Fix DVB-T2 tuning on Linux.

  - Fix encrypted DVD playback.

  - Fix v4l2 frequency conversion.

  + Decoders :

  - Fix numerous issues (M2TS, VC1 interlaced, Lagarith,
    FFv1.3, Xvid) by updating codec libraries.

  - Bring fluidsynth back on Mac OS X

  - Fix some Opus crashes with some filters

  - Fix teletext crash on Windows

  + Demuxers :

  - Avoid an infinite recursion in MKV tags parsing

  - Fix an issue with some Vobsub tracks

  - Fix missing samples at the end of some wav files

  - Fix divide by 0 on ASF/WMV parsing

  + Audio output :

  - Fix audio device selection via command line on Mac OS X

  - Fix audio crashes on Mac OS X

  + Video Output :

  - Fix selection of DirectDraw as the default output for XP

  - Fix transform off-by-one issue

  - Fix screensaver disabling on Windows outputs

  - Fix DirectDraw device enumeration and multi-display
    output

  - Fix a potential crash when playing a fullscreen game at
    the same time as VLC

  + Stream output :

  - Fix 24bits audio MTU alignment in RTP

  - Fix record file names

  + Qt interface :

  - Fix minimal size possible on start

  - Fix a crash with the simple volume widget

  - Fix a crash in the audio menu building

  - Fix multimedia keys issues on Windows

  - Fix opening of DVD and BD folders on Windows

  + HTTP interface: Fix album art display on Windows.

  + Updated translations.

  - Add update-desktop-files BuildRequires and
    %desktop_database_post/postun calls to respective
    scriptlets: Fix
    https://bugs.links2linux.org/browse/PM-108

  - Update to version 2.1.2 :

  + Audio output :

  - Fix digital playback on OS X when more than one audio
    device is installed.

  - Fix digital playback (SPDIF/HDMI) on Windows.

  - Fix stuttering or silent playback when using sound
    enhancers or external audio devices on OS X.

  - Improve responsiveness on OS X when playback starts or
    is being paused.

  - Improve responsiveness, silent playback intervals and
    reliability on iOS.

  + Demuxers :

  - Fix Vimeo and DailyMotion parsing.

  - Various WMV playback improvements and fixes.

  + Decoders :

  - Fix LPCM 20/24-bit decoding and 16 bits with channel
    padding.

  - Fix playback of some HEVC samples.

  + Video filters: Fix crash on deinterlace selection.

  + Qt interface :

  - Fix some streaming profiles when copy existed.

  - Improve A-B loop control.

  - Fix album art update when changing media.

  + Mac OS X interface adjustments.

  + Win32 installer: Kill running VLC process on
    uninstall/update.

  + Updated translations.

  - More features (by adding BuildRequires) :

  + IDN Support (International Domain Names): libidn-devel

  + SFTP Access: libssh2-devel

  + HotKey Support: xcb-util-keysyms-devel

  + Complete SDL Stack: SDL_image-devel

  + ProjectM suppor (for openSUSE >= 12.3)

  - Update to version 2.1.1 :

  + Core :

  - Fix random and reshuffling behaviour.

  - Fix recording.

  - Fix some subtitles track selection.

  + Decoders :

  - VP9 support in WebM.

  - HEVC/H.265 support in MKV, MP4 and raw files.

  - Fix GPU decoding under Windows (DxVA2) crashes.

  + Demuxers :

  - Fix crashes on wav, mlp and mkv and modplug files.

  - Support Speex in ogg files.

  - Fix some .mov playlists support.

  - Support Alac in mkv.

  - Fix WMV3 and palette in AVI.

  - Fix FLAC packetizer issues in some files.

  + Access :

  - Fix DVB options parsing.

  - Fix DeckLink HDMI input.

  - Fix HTTPS connectivity on OS X by loading root
    certificates from Keychain.

  + Audio output :

  - Fixes for DirectSound pass-through.

  - Fixes for OSS output, notably on BSD.

  + Interfaces :

  - Fix HTTP interface infinite loop.

  - Fix D-Bus volume setting.

  + Qt :

  - Reinstore right click subtitle menu to open a subtitle.

  - Fix saving the hotkeys in preferences.

  - Fix saving the audio volume on Win32, using DirectSound.

  - Fix play after drag'n drop.

  - Fix streaming options edition and scale parameter.

  + Stream out :

  - Fix transcoding audio drift issues.

  - Fix numerous audio encoding issues.

  + Win32 installer :

  - Important rewrite to fix numerous bugs, notably about
    updates.

  - Simplification of the upgrade mechanism.

  + Mac OS X interface :

  - Reintroduce the language selector known from pre-2.1
    releases.

  - Fix fullscreen behaviour and various crashes.

  - Fix about dialog crash in Japanese.

  - Fix crashes on proxy lookups.

  - Fixes on the playlist and information behaviours.

  - Fixes on the streaming dialogs.

  - Improves interface resizings.

  + Updated translations.

  - Pass --with-default-font=[path] and

    --with-default-monospace-font=[path] to configure.

  - Drop fix_font_path.patch: replaced with configure
    parameters above.

  - Recommend 'vlc' by vlc-qt: some users might go
    installing the UI package directly. Having Qt most
    likely also means the user has X, so we at least
    recommend the vlc package relying on X.

  - Force creation of plugins cache in vlc-nox %post,
    instead of just touching the file, for details see
    https://trac.videolan.org/vlc/ticket/9807#comment:2

  - Update License: A lot has been relicensed to LGPL-2.1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.links2linux.org/browse/PM-108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://trac.videolan.org/vlc/ticket/9807#comment:2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vlc packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore7-debuginfo");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/22");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libvlc5-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvlc5-debuginfo-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvlccore7-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvlccore7-debuginfo-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-debuginfo-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-debugsource-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-devel-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-gnome-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-gnome-debuginfo-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-noX-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-noX-debuginfo-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-noX-lang-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-qt-2.1.3-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vlc-qt-debuginfo-2.1.3-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vlc");
}
