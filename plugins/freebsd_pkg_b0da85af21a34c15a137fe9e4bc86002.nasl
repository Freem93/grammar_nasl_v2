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

include("compat.inc");

if (description)
{
  script_id(87178);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/29 14:44:44 $");

  script_cve_id("CVE-2015-6761", "CVE-2015-8216", "CVE-2015-8217", "CVE-2015-8218", "CVE-2015-8219", "CVE-2015-8363", "CVE-2015-8364", "CVE-2015-8365");

  script_name(english:"FreeBSD : ffmpeg -- multiple vulnerabilities (b0da85af-21a3-4c15-a137-fe9e4bc86002)");
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

The update_dimensions function in libavcodec/vp8.c in FFmpeg through
2.8.1, as used in Google Chrome before 46.0.2490.71 and other
products, relies on a coefficient-partition count during
multi-threaded operation, which allows remote attackers to cause a
denial of service (race condition and memory corruption) or possibly
have unspecified other impact via a crafted WebM file.

The ljpeg_decode_yuv_scan function in libavcodec/mjpegdec.c in FFmpeg
before 2.8.2 omits certain width and height checks, which allows
remote attackers to cause a denial of service (out-of-bounds array
access) or possibly have unspecified other impact via crafted MJPEG
data.

The ff_hevc_parse_sps function in libavcodec/hevc_ps.c in FFmpeg
before 2.8.2 does not validate the Chroma Format Indicator, which
allows remote attackers to cause a denial of service (out-of-bounds
array access) or possibly have unspecified other impact via crafted
High Efficiency Video Coding (HEVC) data.

The decode_uncompressed function in libavcodec/faxcompr.c in FFmpeg
before 2.8.2 does not validate uncompressed runs, which allows remote
attackers to cause a denial of service (out-of-bounds array access) or
possibly have unspecified other impact via crafted CCITT FAX data.

The init_tile function in libavcodec/jpeg2000dec.c in FFmpeg before
2.8.2 does not enforce minimum-value and maximum-value constraints on
tile coordinates, which allows remote attackers to cause a denial of
service (out-of-bounds array access) or possibly have unspecified
other impact via crafted JPEG 2000 data.

The jpeg2000_read_main_headers function in libavcodec/jpeg2000dec.c in
FFmpeg before 2.6.5, 2.7.x before 2.7.3, and 2.8.x through 2.8.2 does
not enforce uniqueness of the SIZ marker in a JPEG 2000 image, which
allows remote attackers to cause a denial of service (out-of-bounds
heap-memory access) or possibly have unspecified other impact via a
crafted image with two or more of these markers.

Integer overflow in the ff_ivi_init_planes function in
libavcodec/ivi.c in FFmpeg before 2.6.5, 2.7.x before 2.7.3, and 2.8.x
through 2.8.2 allows remote attackers to cause a denial of service
(out-of-bounds heap-memory access) or possibly have unspecified other
impact via crafted image dimensions in Indeo Video Interactive data.

The smka_decode_frame function in libavcodec/smacker.c in FFmpeg
before 2.6.5, 2.7.x before 2.7.3, and 2.8.x through 2.8.2 does not
verify that the data size is consistent with the number of channels,
which allows remote attackers to cause a denial of service
(out-of-bounds array access) or possibly have unspecified other impact
via crafted Smacker data."
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=dabea74d0e82ea80cd344f630497cafcb3ef872c
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df1a1bd8"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=d24888ef19ba38b787b11d1ee091a3d94920c76a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?863da8c9"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=93f30f825c08477fe8f76be00539e96014cc83c8
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f905b5c0"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=d4a731b84a08f0f3839eaaaf82e97d8d9c67da46
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abf9f942"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=43492ff3ab68a343c1264801baa1d5a02de10167
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38aeb8a2"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=44a7f17d0b20e6f8d836b2957e3e357b639f19a2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83fa2994"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=df91aa034b82b77a3c4e01791f4a2b2ff6c82066
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9020836"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=4a9af07a49295e014b059c1ab624c40345af5892
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a67cce36"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ffmpeg.org/security.html"
  );
  # http://www.freebsd.org/ports/portaudit/b0da85af-21a3-4c15-a137-fe9e4bc86002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79880509"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:handbrake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:kodi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mencoder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mythtv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mythtv-frontend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:plexhometheater");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/03");
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
if (pkg_test(save_report:TRUE, pkg:"gstreamer-ffmpeg>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"handbrake>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg>=2.8,1<2.8.3,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg<2.7.3,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg26<2.6.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg25<2.5.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg24<2.4.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg-devel>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg23>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg2>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg1>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg-011>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg0>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"avidemux>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"avidemux2>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"avidemux26>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"kodi<16.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer<1.1.r20150822_7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mencoder<1.1.r20150822_7")) flag++;
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
