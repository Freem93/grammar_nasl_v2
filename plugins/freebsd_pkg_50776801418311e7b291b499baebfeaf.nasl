#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2017 Jacques Vidrine and contributors
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
  script_id(100441);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/26 15:15:35 $");

  script_cve_id("CVE-2017-5506", "CVE-2017-5507", "CVE-2017-5508", "CVE-2017-5509", "CVE-2017-5510", "CVE-2017-5511", "CVE-2017-6497", "CVE-2017-6498", "CVE-2017-6499", "CVE-2017-6500", "CVE-2017-6501", "CVE-2017-6502", "CVE-2017-7275", "CVE-2017-7606", "CVE-2017-7619", "CVE-2017-7941", "CVE-2017-7942", "CVE-2017-7943", "CVE-2017-8343", "CVE-2017-8344", "CVE-2017-8345", "CVE-2017-8346", "CVE-2017-8347", "CVE-2017-8348", "CVE-2017-8349", "CVE-2017-8350", "CVE-2017-8351", "CVE-2017-8352", "CVE-2017-8353", "CVE-2017-8354", "CVE-2017-8355", "CVE-2017-8356", "CVE-2017-8357", "CVE-2017-8365", "CVE-2017-8830", "CVE-2017-9141", "CVE-2017-9142", "CVE-2017-9143", "CVE-2017-9144");

  script_name(english:"FreeBSD : imagemagick -- multiple vulnerabilities (50776801-4183-11e7-b291-b499baebfeaf)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"- CVE-2017-5506: Double free vulnerability in magick/profile.c in
ImageMagick allows remote attackers to have unspecified impact via a
crafted file.

- CVE-2017-5507: Memory leak in coders/mpc.c in ImageMagick before
6.9.7-4 and 7.x before 7.0.4-4 allows remote attackers to cause a
denial of service (memory consumption) via vectors involving a pixel
cache.

- CVE-2017-5508: Heap-based buffer overflow in the PushQuantumPixel
function in ImageMagick before 6.9.7-3 and 7.x before 7.0.4-3 allows
remote attackers to cause a denial of service (application crash) via
a crafted TIFF file.

- CVE-2017-5509: coders/psd.c in ImageMagick allows remote attackers
to have unspecified impact via a crafted PSD file, which triggers an
out-of-bounds write.

- CVE-2017-5510: coders/psd.c in ImageMagick allows remote attackers
to have unspecified impact via a crafted PSD file, which triggers an
out-of-bounds write.

- CVE-2017-5511: coders/psd.c in ImageMagick allows remote attackers
to have unspecified impact by leveraging an improper cast, which
triggers a heap-based buffer overflow.

- CVE-2017-6497: An issue was discovered in ImageMagick 6.9.7. A
specially crafted psd file could lead to a NULL pointer dereference
(thus, a DoS).

- CVE-2017-6498: An issue was discovered in ImageMagick 6.9.7.
Incorrect TGA files could trigger assertion failures, thus leading to
DoS.

- CVE-2017-6499: An issue was discovered in Magick++ in ImageMagick
6.9.7. A specially crafted file creating a nested exception could lead
to a memory leak (thus, a DoS).

- CVE-2017-6500: An issue was discovered in ImageMagick 6.9.7. A
specially crafted sun file triggers a heap-based buffer over-read.

- CVE-2017-6501: An issue was discovered in ImageMagick 6.9.7. A
specially crafted xcf file could lead to a NULL pointer dereference.

- CVE-2017-6502: An issue was discovered in ImageMagick 6.9.7. A
specially crafted webp file could lead to a file-descriptor leak in
libmagickcore (thus, a DoS).

- CVE-2017-7275: The ReadPCXImage function in coders/pcx.c in
ImageMagick 7.0.4.9 allows remote attackers to cause a denial of
service (attempted large memory allocation and application crash) via
a crafted file. NOTE: this vulnerability exists because of an
incomplete fix for CVE-2016-8862 and CVE-2016-8866.

- CVE-2017-7606: coders/rle.c in ImageMagick 7.0.5-4 has an 'outside
the range of representable values of type unsigned char' undefined
behavior issue, which might allow remote attackers to cause a denial
of service (application crash) or possibly have unspecified other
impact via a crafted image.

- CVE-2017-7619: In ImageMagick 7.0.4-9, an infinite loop can occur
because of a floating-point rounding error in some of the color
algorithms. This affects ModulateHSL, ModulateHCL, ModulateHCLp,
ModulateHSB, ModulateHSI, ModulateHSV, ModulateHWB, ModulateLCHab, and
ModulateLCHuv.

- CVE-2017-7941: The ReadSGIImage function in sgi.c allows remote
attackers to consume an amount of available memory via a crafted file.

- CVE-2017-7942: The ReadAVSImage function in avs.c allows remote
attackers to consume an amount of available memory via a crafted file.

- CVE-2017-7943: The ReadSVGImage function in svg.c allows remote
attackers to consume an amount of available memory via a crafted file.

- CVE-2017-8343: ReadAAIImage function in aai.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8344: ReadPCXImage function in pcx.c allows attackers to
cause a denial of service (memory leak) via a crafted file. The
ReadMNGImage function in png.c allows attackers to cause a denial of
service (memory leak) via a crafted file.

- CVE-2017-8345: ReadMNGImage function in png.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8346: ReadMATImage function in mat.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8347: ReadMATImage function in mat.c allows attackers to
cause a denial of service (memory leak) via a crafted file. 

- CVE-2017-8348: ReadMATImage function in mat.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8349: ReadSFWImage function in sfw.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8350: ReadJNGImage function in png.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8351: ReadPCDImage function in pcd.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8352: ReadXWDImage function in xwd.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8353: ReadPICTImage function in pict.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8354: ReadBMPImage function in bmp.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8355: ReadMTVImage function in mtv.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8356: ReadSUNImage function in sun.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8357: ReadEPTImage function in ept.c allows attackers to
cause a denial of service (memory leak) via a crafted file.

- CVE-2017-8365: The function named ReadICONImage in coders\icon.c has
a memory leak vulnerability which can cause memory exhaustion via a
crafted ICON file.

- CVE-2017-8830: ReadBMPImage function in bmp.c:1379 allows attackers
to cause a denial of service (memory leak) via a crafted file.

- CVE-2017-9141: A crafted file could trigger an assertion failure in
the ResetImageProfileIterator function in MagickCore/profile.c because
of missing checks in the ReadDDSImage function in coders/dds.c.

- CVE-2017-9142: A crafted file could trigger an assertion failure in
the WriteBlob function in MagickCore/blob.c because of missing checks
in the ReadOneJNGImage function in coders/png.c.

- CVE-2017-9143: ReadARTImage function in coders/art.c allows
attackers to cause a denial of service (memory leak) via a crafted
.art file.

- CVE-2017-9144: A crafted RLE image can trigger a crash because of
incorrect EOF handling in coders/rle.c."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nvd.nist.gov/vuln/search/results?query=ImageMagick"
  );
  # http://www.freebsd.org/ports/portaudit/50776801-4183-11e7-b291-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ebd8e756"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"imagemagick<6.9.8.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");


