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
  script_id(26978);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/08 20:42:12 $");

  script_cve_id("CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4987", "CVE-2007-4988");

  script_name(english:"FreeBSD : ImageMagick -- multiple vulnerabilities (f5b29ec0-71f9-11dc-8c6a-00304881ac9a)");
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
"Multiple vulnerabilities have been discovered in ImageMagick.

ImageMagick before 6.3.5-9 allows context-dependent attackers to cause
a denial of service via a crafted image file that triggers (1) an
infinite loop in the ReadDCMImage function, related to ReadBlobByte
function calls; or (2) an infinite loop in the ReadXCFImage function,
related to ReadBlobMSBLong function calls.

Multiple integer overflows in ImageMagick before 6.3.5-9 allow
context-dependent attackers to execute arbitrary code via a crafted
(1) .dcm, (2) .dib, (3) .xbm, (4) .xcf, or (5) .xwd image file, which
triggers a heap-based buffer overflow.

Off-by-one error in the ReadBlobString function in blob.c in
ImageMagick before 6.3.5-9 allows context-dependent attackers to
execute arbitrary code via a crafted image file, which triggers the
writing of a '\0' character to an out-of-bounds address.

Sign extension error in the ReadDIBImage function in ImageMagick
before 6.3.5-9 allows context-dependent attackers to execute arbitrary
code via a crafted width value in an image file, which triggers an
integer overflow and a heap-based buffer overflow."
  );
  # http://studio.imagemagick.org/pipermail/magick-announce/2007-September/000037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a73507c"
  );
  # http://www.freebsd.org/ports/portaudit/f5b29ec0-71f9-11dc-8c6a-00304881ac9a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a4d35ff"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ImageMagick-nox11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"ImageMagick<6.3.5.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ImageMagick-nox11<6.3.5.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
