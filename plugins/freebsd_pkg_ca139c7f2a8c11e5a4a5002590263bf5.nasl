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
  script_id(84782);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/08 20:42:12 $");

  script_cve_id("CVE-2004-0941", "CVE-2007-0455", "CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3477", "CVE-2009-3546", "CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696");
  script_bugtraq_id(11663, 22289, 24089, 24651, 36712);

  script_name(english:"FreeBSD : libwmf -- multiple vulnerabilities (ca139c7f-2a8c-11e5-a4a5-002590263bf5)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mitre reports :

Multiple buffer overflows in the gd graphics library (libgd) 2.0.21
and earlier may allow remote attackers to execute arbitrary code via
malformed image files that trigger the overflows due to improper calls
to the gdMalloc function, a different set of vulnerabilities than
CVE-2004-0990.

Buffer overflow in the gdImageStringFTEx function in gdft.c in GD
Graphics Library 2.0.33 and earlier allows remote attackers to cause a
denial of service (application crash) and possibly execute arbitrary
code via a crafted string with a JIS encoded font.

The gdPngReadData function in libgd 2.0.34 allows user-assisted
attackers to cause a denial of service (CPU consumption) via a crafted
PNG image with truncated data, which causes an infinite loop in the
png_read_info function in libpng.

Integer overflow in gdImageCreateTrueColor function in the GD Graphics
Library (libgd) before 2.0.35 allows user-assisted remote attackers to
have unspecified attack vectors and impact.

The gdImageCreateXbm function in the GD Graphics Library (libgd)
before 2.0.35 allows user-assisted remote attackers to cause a denial
of service (crash) via unspecified vectors involving a gdImageCreate
failure.

The (a) imagearc and (b) imagefilledarc functions in GD Graphics
Library (libgd) before 2.0.35 allow attackers to cause a denial of
service (CPU consumption) via a large (1) start or (2) end angle
degree value.

The _gdGetColors function in gd_gd.c in PHP 5.2.11 and 5.3.x before
5.3.1, and the GD Graphics Library 2.x, does not properly verify a
certain colorsTotal structure member, which might allow remote
attackers to conduct buffer overflow or buffer over-read attacks via a
crafted GD file, a different vulnerability than CVE-2009-3293. NOTE:
some of these details are obtained from third party information.

Heap-based buffer overflow in libwmf 0.2.8.4 allows remote attackers
to cause a denial of service (crash) or possibly execute arbitrary
code via a crafted BMP image.

meta.h in libwmf 0.2.8.4 allows remote attackers to cause a denial of
service (out-of-bounds read) via a crafted WMF file.

Use-after-free vulnerability in libwmf 0.2.8.4 allows remote attackers
to cause a denial of service (crash) via a crafted WMF file to the (1)
wmf2gd or (2) wmf2eps command.

Heap-based buffer overflow in the DecodeImage function in libwmf
0.2.8.4 allows remote attackers to cause a denial of service (crash)
or possibly execute arbitrary code via a crafted 'run-length count' in
an image in a WMF file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=201513"
  );
  # http://www.freebsd.org/ports/portaudit/ca139c7f-2a8c-11e5-a4a5-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22b4cd26"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libwmf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");
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

if (pkg_test(save_report:TRUE, pkg:"libwmf<0.2.8.4_14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
