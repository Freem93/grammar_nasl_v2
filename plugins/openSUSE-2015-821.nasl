#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-821.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87085);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/30 15:53:21 $");

  script_cve_id("CVE-2015-8216", "CVE-2015-8217", "CVE-2015-8218", "CVE-2015-8219");

  script_name(english:"openSUSE Security Update : ffmpeg (openSUSE-2015-821)");
  script_summary(english:"Check for the openSUSE-2015-821 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ffmpeg package was updated to version 2.8.2 to fix the following
security and non security issues :

  - CVE-2015-8216: Fixed the ljpeg_decode_yuv_scan function
    in libavcodec/mjpegdec.c which could cause a denial of
    service (out-of-bounds array access) (bnc#955346).

  - CVE-2015-8217: Fixed the ff_hevc_parse_sps function in
    libavcodec/hevc_ps.c which could cause a denial of
    service (out-of-bounds array access) (bnc#955347).

  - CVE-2015-8218: Fixed the decode_uncompressed function in
    libavcodec/faxcompr.c which could cause a denial of
    service (out-of-bounds array access) (bnc#955348).

  - CVE-2015-8219: Fixed the init_tile function in
    libavcodec/jpeg2000dec.c which could cause a denial of
    service (out-of-bounds array access) (bnc#955350).

  - Update to new upstream release 2.8.2

  - various fixes in the aac_fixed decoder

  - various fixes in softfloat

  - swresample/resample: increase precision for compensation

  - lavf/mov: add support for sidx fragment indexes

  - avformat/mxfenc: Only store user comment related tags
    when needed

  - ffmpeg: Don't try and write sdp info if none of the
    outputs had an rtp format.

  - apng: use correct size for output buffer

  - jvdec: avoid unsigned overflow in comparison

  - avcodec/jpeg2000dec: Clip all tile coordinates

  - avcodec/microdvddec: Check for string end in 'P' case

  - avcodec/dirac_parser: Fix undefined memcpy() use

  - avformat/xmv: Discard remainder of packet on error

  - avformat/xmv: factor return check out of if/else

  - avcodec/mpeg12dec: Do not call show_bits() with invalid
    bits

  - avcodec/faxcompr: Add missing runs check in
    decode_uncompressed()

  - libavutil/channel_layout: Check strtol*() for failure

  - avformat/mpegts: Only start probing data streams within
    probe_packets

  - avcodec/hevc_ps: Check chroma_format_idc

  - avcodec/ffv1dec: Check for 0 quant tables

  - avcodec/mjpegdec: Reinitialize IDCT on BPP changes

  - avcodec/mjpegdec: Check index in ljpeg_decode_yuv_scan()
    before using it

  - avcodec/h264_slice: Disable slice threads if there are
    multiple access units in a packet

  - avformat/hls: update cookies on setcookie response

  - opusdec: Don't run vector_fmul_scalar on zero length
    arrays

  - avcodec/opusdec: Fix extra samples read index

  - avcodec/ffv1: Initialize vlc_state on allocation

  - avcodec/ffv1dec: update progress in case of broken
    pointer chains

  - avcodec/ffv1dec: Clear slice coordinates if they are
    invalid or slice header decoding fails for other reasons

  - rtsp: Allow $ as interleaved packet indicator before a
    complete response header

  - videodsp: don't overread edges in vfix3 emu_edge.

  - avformat/mp3dec: improve junk skipping heuristic

  - concatdec: fix file_start_time calculation regression

  - avcodec: loongson optimize h264dsp idct and loop filter
    with mmi

  - avcodec/jpeg2000dec: Clear properties in
    jpeg2000_dec_cleanup() too

  - avformat/hls: add support for EXT-X-MAP

  - avformat/hls: fix segment selection regression on track
    changes of live streams

  - configure: Require libkvazaar < 0.7.

  - avcodec/vp8: Do not use num_coeff_partitions in
    thread/buffer setup

  - Drop ffmpeg-mov-sidx-fragment.patch, fixed upstream.

  - Update to new upstream release 2.8.1

  - Minor bugfix release

  - Includes all changes from. Ffmpeg-mt, libav master of
    2015-08-28, libav 11 as of 2015-08-28

  - Add ffmpeg-mov-sidx-fragment.patch to add sidx fragment
    indexes. Needed for new mpv release."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955350"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ffmpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/30");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-debuginfo-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-debugsource-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-devel-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec-devel-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec56-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec56-debuginfo-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice-devel-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice56-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice56-debuginfo-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter-devel-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter5-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter5-debuginfo-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat-devel-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat56-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat56-debuginfo-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample-devel-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample2-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample2-debuginfo-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil-devel-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil54-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil54-debuginfo-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc-devel-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc53-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc53-debuginfo-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample-devel-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample1-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample1-debuginfo-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale-devel-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale3-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale3-debuginfo-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavcodec56-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavcodec56-debuginfo-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavdevice56-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavdevice56-debuginfo-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavfilter5-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavfilter5-debuginfo-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavformat56-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavformat56-debuginfo-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavresample2-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavresample2-debuginfo-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavutil54-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavutil54-debuginfo-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpostproc53-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpostproc53-debuginfo-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswresample1-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswresample1-debuginfo-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswscale3-32bit-2.8.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswscale3-debuginfo-32bit-2.8.2-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg / ffmpeg-debuginfo / ffmpeg-debugsource / ffmpeg-devel / etc");
}
