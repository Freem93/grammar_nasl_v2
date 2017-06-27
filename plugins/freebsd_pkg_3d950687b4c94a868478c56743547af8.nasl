#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(86044);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/21 13:46:13 $");

  script_cve_id("CVE-2015-6818", "CVE-2015-6819", "CVE-2015-6820", "CVE-2015-6821", "CVE-2015-6822", "CVE-2015-6823", "CVE-2015-6824", "CVE-2015-6825", "CVE-2015-6826");

  script_name(english:"FreeBSD : ffmpeg -- multiple vulnerabilities (3d950687-b4c9-4a86-8478-c56743547af8)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NVD reports :

The decode_ihdr_chunk function in libavcodec/pngdec.c in FFmpeg before
2.7.2 does not enforce uniqueness of the IHDR (aka image header) chunk
in a PNG image, which allows remote attackers to cause a denial of
service (out-of-bounds array access) or possibly have unspecified
other impact via a crafted image with two or more of these chunks.

Multiple integer underflows in the ff_mjpeg_decode_frame function in
libavcodec/mjpegdec.c in FFmpeg before 2.7.2 allow remote attackers to
cause a denial of service (out-of-bounds array access) or possibly
have unspecified other impact via crafted MJPEG data.

The ff_sbr_apply function in libavcodec/aacsbr.c in FFmpeg before
2.7.2 does not check for a matching AAC frame syntax element before
proceeding with Spectral Band Replication calculations, which allows
remote attackers to cause a denial of service (out-of-bounds array
access) or possibly have unspecified other impact via crafted AAC
data.

The ff_mpv_common_init function in libavcodec/mpegvideo.c in FFmpeg
before 2.7.2 does not properly maintain the encoding context, which
allows remote attackers to cause a denial of service (invalid pointer
access) or possibly have unspecified other impact via crafted MPEG
data.

The destroy_buffers function in libavcodec/sanm.c in FFmpeg before
2.7.2 does not properly maintain height and width values in the video
context, which allows remote attackers to cause a denial of service
(segmentation violation and application crash) or possibly have
unspecified other impact via crafted LucasArts Smush video data.

The allocate_buffers function in libavcodec/alac.c in FFmpeg before
2.7.2 does not initialize certain context data, which allows remote
attackers to cause a denial of service (segmentation violation) or
possibly have unspecified other impact via crafted Apple Lossless
Audio Codec (ALAC) data.

The sws_init_context function in libswscale/utils.c in FFmpeg before
2.7.2 does not initialize certain pixbuf data structures, which allows
remote attackers to cause a denial of service (segmentation violation)
or possibly have unspecified other impact via crafted video data.

The ff_frame_thread_init function in libavcodec/pthread_frame.c in
FFmpeg before 2.7.2 mishandles certain memory-allocation failures,
which allows remote attackers to cause a denial of service (invalid
pointer access) or possibly have unspecified other impact via a
crafted file, as demonstrated by an AVI file.

The ff_rv34_decode_init_thread_copy function in libavcodec/rv34.c in
FFmpeg before 2.7.2 does not initialize certain structure members,
which allows remote attackers to cause a denial of service (invalid
pointer access) or possibly have unspecified other impact via crafted
(1) RV30 or (2) RV40 RealVideo data."
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=47f4e2d8960ca756ca153ab8e3e93d80449b8c91
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8d88c08"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=84afc6b70d24fc0bf686e43138c96cf60a9445fe
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e49cc8b"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=79a98294da6cd85f8c86b34764c5e0c43b09eea3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a2d733c"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=b160fc290cf49b516c5b6ee0730fd9da7fc623b1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0b4c85d"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=39bbdebb1ed8eb9c9b0cd6db85afde6ba89d86e4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9901608"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=f7068bf277a37479aecde2832208d820682b35e6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df0e4e28"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=a5d44d5c220e12ca0cb7a4eceb0f74759cb13111
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?553afebc"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=f1a38264f20382731cf2cc75fdd98f4c9a84a626
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7482a81"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=3197c0aa87a3b7190e17d49e6fbc7b554e4b3f0a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b0a7abe"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ffmpeg.org/security.html"
  );
  # http://www.freebsd.org/ports/portaudit/3d950687-b4c9-4a86-8478-c56743547af8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6150b5fc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:avidemux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:avidemux2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:avidemux26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg-011");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gstreamer-ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gstreamer1-libav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:handbrake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:kodi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mencoder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mythtv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mythtv-frontend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:plexhometheater");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"libav>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gstreamer1-libav<1.5.90")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gstreamer-ffmpeg>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"handbrake>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg<2.7.2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg26<2.6.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg25<2.5.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg24<2.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg-devel>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg23>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg2>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg1>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg-011>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg0>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"avidemux<2.6.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"avidemux2<2.6.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"avidemux26<2.6.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"kodi<15.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer<1.1.r20150822")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mencoder<1.1.r20150822")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mythtv>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mythtv-frontend>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"plexhometheater>=0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
