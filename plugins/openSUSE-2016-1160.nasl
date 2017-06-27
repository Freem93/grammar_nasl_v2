#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1160.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93996);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/12 13:47:11 $");

  script_name(english:"openSUSE Security Update : ffmpeg (openSUSE-2016-1160)");
  script_summary(english:"Check for the openSUSE-2016-1160 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ffmpeg was updated to 2.8.8 to fix the following issues, both bugs and
security issues :

  - avformat/oggparsevp8: fix pts calculation on pages
    ending with an invisible frame

  - avcodec/mjpegdec: Do not try to detect last scan but
    apply idct after all scans for progressive jpeg

  - avformat/oggparseopus: Check that granule pos is within
    the supported range

  - avformat/utils: Check bps before using it in a shift in
    ff_get_pcm_codec_id()

  - ffmpeg: Check that r_frame_rate is set before attempting
    to use it

  - avformat/utils: Do not compute the bitrate from duration
    == 0

  - avformat/utils: Check negative bps before shifting in
    ff_get_pcm_codec_id()

  - avformat/avidec: Detect index with too short entries

  - avformat/oggparseopus: Fix Undefined behavior in
    oggparseopus.c and libavformat/utils.c

  - avformat/allformats: Making av_register_all()
    thread-safe.

  - avcodec/vp9_parser: Check the input frame sizes for
    being consistent

  - avformat/oggdec: Fix integer overflow with invalid pts

  - avcodec/ffv1enc: Fix assertion failure with non zero
    bits per sample

  - avcodec/diracdec: Check numx/y

  - avformat/avidec: Fix infinite loop in avi_read_nikon()"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998636"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ffmpeg packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-debuginfo-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-debugsource-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-devel-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec-devel-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec56-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec56-debuginfo-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice-devel-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice56-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice56-debuginfo-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter-devel-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter5-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter5-debuginfo-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat-devel-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat56-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat56-debuginfo-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample-devel-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample2-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample2-debuginfo-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil-devel-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil54-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil54-debuginfo-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc-devel-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc53-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc53-debuginfo-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample-devel-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample1-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample1-debuginfo-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale-devel-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale3-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale3-debuginfo-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavcodec56-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavcodec56-debuginfo-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavdevice56-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavdevice56-debuginfo-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavfilter5-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavfilter5-debuginfo-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavformat56-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavformat56-debuginfo-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavresample2-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavresample2-debuginfo-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavutil54-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavutil54-debuginfo-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpostproc53-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpostproc53-debuginfo-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswresample1-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswresample1-debuginfo-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswscale3-32bit-2.8.8-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswscale3-debuginfo-32bit-2.8.8-19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg / ffmpeg-debuginfo / ffmpeg-debugsource / ffmpeg-devel / etc");
}
