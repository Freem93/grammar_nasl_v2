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

include("compat.inc");

if (description)
{
  script_id(99551);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/21 13:44:39 $");

  script_cve_id("CVE-2017-5225", "CVE-2017-7592", "CVE-2017-7593", "CVE-2017-7594", "CVE-2017-7595", "CVE-2017-7596", "CVE-2017-7597", "CVE-2017-7598", "CVE-2017-7599", "CVE-2017-7600", "CVE-2017-7601", "CVE-2017-7602");

  script_name(english:"FreeBSD : tiff -- multiple vulnerabilities (2a96e498-3234-4950-a9ad-419bc84a839d)");
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

LibTIFF version 4.0.7 is vulnerable to a heap buffer overflow in the
tools/tiffcp resulting in DoS or code execution via a crafted
BitsPerSample value.

The putagreytile function in tif_getimage.c in LibTIFF 4.0.7 has a
left-shift undefined behavior issue, which might allow remote
attackers to cause a denial of service (application crash) or possibly
have unspecified other impact via a crafted image.

tif_read.c in LibTIFF 4.0.7 does not ensure that tif_rawdata is
properly initialized, which might allow remote attackers to obtain
sensitive information from process memory via a crafted image.

The OJPEGReadHeaderInfoSecTablesDcTable function in tif_ojpeg.c in
LibTIFF 4.0.7 allows remote attackers to cause a denial of service
(memory leak) via a crafted image.

The JPEGSetupEncode function in tiff_jpeg.c in LibTIFF 4.0.7 allows
remote attackers to cause a denial of service (divide-by-zero error
and application crash) via a crafted image.

LibTIFF 4.0.7 has an 'outside the range of representable values of
type float' undefined behavior issue, which might allow remote
attackers to cause a denial of service (application crash) or possibly
have unspecified other impact via a crafted image.

tif_dirread.c in LibTIFF 4.0.7 has an 'outside the range of
representable values of type float' undefined behavior issue, which
might allow remote attackers to cause a denial of service (application
crash) or possibly have unspecified other impact via a crafted image.

tif_dirread.c in LibTIFF 4.0.7 might allow remote attackers to cause a
denial of service (divide-by-zero error and application crash) via a
crafted image.

LibTIFF 4.0.7 has an 'outside the range of representable values of
type short' undefined behavior issue, which might allow remote
attackers to cause a denial of service (application crash) or possibly
have unspecified other impact via a crafted image.

LibTIFF 4.0.7 has an 'outside the range of representable values of
type unsigned char' undefined behavior issue, which might allow remote
attackers to cause a denial of service (application crash) or possibly
have unspecified other impact via a crafted image.

LibTIFF 4.0.7 has a 'shift exponent too large for 64-bit type long'
undefined behavior issue, which might allow remote attackers to cause
a denial of service (application crash) or possibly have unspecified
other impact via a crafted image.

LibTIFF 4.0.7 has a signed integer overflow, which might allow remote
attackers to cause a denial of service (application crash) or possibly
have unspecified other impact via a crafted image."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vadz/libtiff/commit/5c080298d59e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vadz/libtiff/commit/48780b4fcc42"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vadz/libtiff/commit/d60332057b95"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vadz/libtiff/commit/2ea32f7372b6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vadz/libtiff/commit/8283e4d1b7e5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vadz/libtiff/commit/47f2fb61a3a6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vadz/libtiff/commit/3cfd62d77c2a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vadz/libtiff/commit/3144e57770c1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vadz/libtiff/commit/0a76a8c765c7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vadz/libtiff/commit/66e7bd595209"
  );
  # http://www.freebsd.org/ports/portaudit/2a96e498-3234-4950-a9ad-419bc84a839d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee8ddb99"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c7-tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-f10-tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-f8-tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
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

if (pkg_test(save_report:TRUE, pkg:"tiff<4.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f8-tiff<4.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-tiff<4.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-tiff<4.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c7-tiff<4.0.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
