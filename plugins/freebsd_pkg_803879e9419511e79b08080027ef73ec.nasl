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
  script_id(100442);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/26 15:15:35 $");

  script_cve_id("CVE-2017-9110", "CVE-2017-9111", "CVE-2017-9112", "CVE-2017-9113", "CVE-2017-9114", "CVE-2017-9115", "CVE-2017-9116");

  script_name(english:"FreeBSD : OpenEXR -- multiple remote code execution and denial of service vulnerabilities (803879e9-4195-11e7-9b08-080027ef73ec)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Brandon Perry reports :

[There] is a zip file of EXR images that cause segmentation faults in
the OpenEXR library (tested against 2.2.0).

- CVE-2017-9110 In OpenEXR 2.2.0, an invalid read of size 2 in the
hufDecode function in ImfHuf.cpp could cause the application to crash.

- CVE-2017-9111 In OpenEXR 2.2.0, an invalid write of size 8 in the
storeSSE function in ImfOptimizedPixelReading.h could cause the
application to crash or execute arbitrary code.

- CVE-2017-9112 In OpenEXR 2.2.0, an invalid read of size 1 in the
getBits function in ImfHuf.cpp could cause the application to crash.

- CVE-2017-9113 In OpenEXR 2.2.0, an invalid write of size 1 in the
bufferedReadPixels function in ImfInputFile.cpp could cause the
application to crash or execute arbitrary code.

- CVE-2017-9114 In OpenEXR 2.2.0, an invalid read of size 1 in the
refill function in ImfFastHuf.cpp could cause the application to
crash.

- CVE-2017-9115 In OpenEXR 2.2.0, an invalid write of size 2 in the =
operator function in half.h could cause the application to crash or
execute arbitrary code.

- CVE-2017-9116 In OpenEXR 2.2.0, an invalid read of size 1 in the
uncompress function in ImfZip.cpp could cause the application to
crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2017/05/12/5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/openexr/openexr/issues/232"
  );
  # http://www.freebsd.org/ports/portaudit/803879e9-4195-11e7-9b08-080027ef73ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a241e53c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:OpenEXR");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/12");
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

if (pkg_test(save_report:TRUE, pkg:"OpenEXR<2.2.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");


