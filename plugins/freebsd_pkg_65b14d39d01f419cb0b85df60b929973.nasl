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
  script_id(83940);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/06/02 13:55:20 $");

  script_cve_id("CVE-2012-5150", "CVE-2014-4609", "CVE-2014-8541", "CVE-2014-8542", "CVE-2014-8543", "CVE-2014-8545", "CVE-2014-8547", "CVE-2014-8548", "CVE-2014-9316", "CVE-2014-9317", "CVE-2014-9603", "CVE-2015-1872");

  script_name(english:"FreeBSD : ffmpeg -- multiple vulnerabilities (65b14d39-d01f-419c-b0b8-5df60b929973)");
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
"NVD and Vigilance report :

Use-after-free vulnerability in Google Chrome before 24.0.1312.52
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving seek operations on
video data.

An attacker can generate an integer overflow in the av_lzo1x_decode()
function of Libav, in order to trigger a denial of service, and
possibly to execute code.

libavcodec/mjpegdec.c in FFmpeg before 2.4.2 considers only dimension
differences, and not bits-per-pixel differences, when determining
whether an image size has changed, which allows remote attackers to
cause a denial of service (out-of-bounds access) or possibly have
unspecified other impact via crafted MJPEG data.

libavcodec/utils.c in FFmpeg before 2.4.2 omits a certain codec ID
during enforcement of alignment, which allows remote attackers to
cause a denial of service (out-of-bounds access) or possibly have
unspecified other impact via crafted JV data.

libavcodec/mmvideo.c in FFmpeg before 2.4.2 does not consider all
lines of HHV Intra blocks during validation of image height, which
allows remote attackers to cause a denial of service (out-of-bounds
access) or possibly have unspecified other impact via crafted MM video
data.

libavcodec/pngdec.c in FFmpeg before 2.4.2 accepts the
monochrome-black format without verifying that the bits-per-pixel
value is 1, which allows remote attackers to cause a denial of service
(out-of-bounds access) or possibly have unspecified other impact via
crafted PNG data.

libavcodec/gifdec.c in FFmpeg before 2.4.2 does not properly compute
image heights, which allows remote attackers to cause a denial of
service (out-of-bounds access) or possibly have unspecified other
impact via crafted GIF data.

Off-by-one error in libavcodec/smc.c in FFmpeg before 2.4.2 allows
remote attackers to cause a denial of service (out-of-bounds access)
or possibly have unspecified other impact via crafted Quicktime
Graphics (aka SMC) video data.

The mjpeg_decode_app function in libavcodec/mjpegdec.c in FFMpeg
before 2.1.6, 2.2.x through 2.3.x, and 2.4.x before 2.4.4 allows
remote attackers to cause a denial of service (out-of-bounds heap
access) and possibly have other unspecified impact via vectors related
to LJIF tags in an MJPEG file.

The decode_ihdr_chunk function in libavcodec/pngdec.c in FFMpeg before
2.1.6, 2.2.x through 2.3.x, and 2.4.x before 2.4.4 allows remote
attackers to cause a denial of service (out-of-bounds heap access) and
possibly have other unspecified impact via an IDAT before an IHDR in a
PNG file.

The vmd_decode function in libavcodec/vmdvideo.c in FFmpeg before
2.5.2 does not validate the relationship between a certain length
value and the frame width, which allows remote attackers to cause a
denial of service (out-of-bounds array access) or possibly have
unspecified other impact via crafted Sierra VMD video data.

An attacker can force a read at an invalid address in mjpegdec.c of
FFmpeg, in order to trigger a denial of service."
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=c3ece52decafc4923aebe7fd74b274e9ebb1962e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df296ca0"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=1b291e0466308b341bc2e8c2a49d44862400f014
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c6b07e9"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=b5e661bcd2bb4fe771cb2c1e21215c68e6a17665
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f66b8867"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=cd3c4d8c55222337b0b59af4ea1fecfb46606e5e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e34f9b86"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=73962e677d871fa0dde5385ee04ea07c048d8864
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?809cd25d"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=7a5590ef4282e19d48d70cba0bc4628c13ec6fd8
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1bcdda5"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=ef32bc8dde52439afd13988f56012a9f4dd55a83
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3c1ea56"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=5b2097626d0e4ccb432d7d8ab040aa8dbde9eb3a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae7031d2"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=30e8a375901f8802853fd6d478b77a127d208bd6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?786afd2c"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=cb1db92cca98f963e91f421ee0c84f8866325a73
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d46cbd8e"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=fac6f744d8170585f05e098ce9c9f27eeffa818e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47cfac9e"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=75b0cfcf105c8720a47a2ee80a70ba16799d71b7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d1c1480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ffmpeg.org/security.html"
  );
  # http://www.freebsd.org/ports/portaudit/65b14d39-d01f-419c-b0b8-5df60b929973.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?291da70f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/02");
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

if (pkg_test(save_report:TRUE, pkg:"ffmpeg<0.7.17,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg0<0.7.17,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
