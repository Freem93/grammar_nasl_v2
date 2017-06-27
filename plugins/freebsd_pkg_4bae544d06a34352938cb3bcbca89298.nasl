#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
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
  script_id(87611);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:02:54 $");

  script_cve_id("CVE-2015-8662", "CVE-2015-8663");

  script_name(english:"FreeBSD : ffmpeg -- multiple vulnerabilities (4bae544d-06a3-4352-938c-b3bcbca89298)");
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

The ff_dwt_decode function in libavcodec/jpeg2000dwt.c in FFmpeg
before 2.8.4 does not validate the number of decomposition levels
before proceeding with Discrete Wavelet Transform decoding, which
allows remote attackers to cause a denial of service (out-of-bounds
array access) or possibly have unspecified other impact via crafted
JPEG 2000 data.

The ff_get_buffer function in libavcodec/utils.c in FFmpeg before
2.8.4 preserves width and height values after a failure, which allows
remote attackers to cause a denial of service (out-of-bounds array
access) or possibly have unspecified other impact via a crafted .mov
file."
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=75422280fbcdfbe9dc56bde5525b4d8b280f1bc5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cd05a78"
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=abee0a1c60612e8638640a8a3738fffb65e16dbf
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?800eb3ec"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ffmpeg.org/security.html"
  );
  # http://www.freebsd.org/ports/portaudit/4bae544d-06a3-4352-938c-b3bcbca89298.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8305b09d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (pkg_test(save_report:TRUE, pkg:"ffmpeg>=2.8,1<2.8.4,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg<2.7.4,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg26<2.6.6")) flag++;
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
if (pkg_test(save_report:TRUE, pkg:"mplayer<1.2.r20151219_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mencoder<1.2.r20151219_1")) flag++;
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
