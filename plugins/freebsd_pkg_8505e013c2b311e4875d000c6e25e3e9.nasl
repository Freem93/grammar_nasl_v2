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
  script_id(81618);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/11 15:46:02 $");

  script_cve_id("CVE-2015-1212", "CVE-2015-1213", "CVE-2015-1214", "CVE-2015-1215", "CVE-2015-1216", "CVE-2015-1217", "CVE-2015-1218", "CVE-2015-1219", "CVE-2015-1220", "CVE-2015-1221", "CVE-2015-1222", "CVE-2015-1223", "CVE-2015-1224", "CVE-2015-1225", "CVE-2015-1226", "CVE-2015-1227", "CVE-2015-1228", "CVE-2015-1229", "CVE-2015-1230", "CVE-2015-1231");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (8505e013-c2b3-11e4-875d-000c6e25e3e9)");
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
"Chrome Releases reports :

51 security fixes in this release, including :

- [456516] High CVE-2015-1212: Out-of-bounds write in media. Credit to
anonymous.

- [448423] High CVE-2015-1213: Out-of-bounds write in skia filters.
Credit to cloudfuzzer.

- [445810] High CVE-2015-1214: Out-of-bounds write in skia filters.
Credit to cloudfuzzer.

- [445809] High CVE-2015-1215: Out-of-bounds write in skia filters.
Credit to cloudfuzzer.

- [454954] High CVE-2015-1216: Use-after-free in v8 bindings. Credit
to anonymous.

- [456192] High CVE-2015-1217: Type confusion in v8 bindings. Credit
to anonymous.

- [456059] High CVE-2015-1218: Use-after-free in dom. Credit to
cloudfuzzer.

- [446164] High CVE-2015-1219: Integer overflow in webgl. Credit to
Chen Zhang (demi6od) of NSFOCUS Security Team.

- [437651] High CVE-2015-1220: Use-after-free in gif decoder. Credit
to Aki Helin of OUSPG.

- [455368] High CVE-2015-1221: Use-after-free in web databases. Credit
to Collin Payne.

- [448082] High CVE-2015-1222: Use-after-free in service workers.
Credit to Collin Payne.

- [454231] High CVE-2015-1223: Use-after-free in dom. Credit to
Maksymillian Motyl.

- High CVE-2015-1230: Type confusion in v8. Credit to Skylined working
with HP's Zero Day Initiative.

- [449958] Medium CVE-2015-1224: Out-of-bounds read in vpxdecoder.
Credit to Aki Helin of OUSPG.

- [446033] Medium CVE-2015-1225: Out-of-bounds read in pdfium. Credit
to cloudfuzzer.

- [456841] Medium CVE-2015-1226: Validation issue in debugger. Credit
to Rob Wu.

- [450389] Medium CVE-2015-1227: Uninitialized value in blink. Credit
to Christoph Diehl.

- [444707] Medium CVE-2015-1228: Uninitialized value in rendering.
Credit to miaubiz.

- [431504] Medium CVE-2015-1229: Cookie injection via proxies. Credit
to iliwoy.

- [463349] CVE-2015-1231: Various fixes from internal audits, fuzzing,
and other initiatives."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://googlechromereleases.blogspot.nl"
  );
  # http://www.freebsd.org/ports/portaudit/8505e013-c2b3-11e4-875d-000c6e25e3e9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e15341b0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<41.0.2272.76")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<41.0.2272.76")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<41.0.2272.76")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
