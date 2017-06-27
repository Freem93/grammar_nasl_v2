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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(84994);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/19 14:02:55 $");

  script_cve_id("CVE-2015-1270", "CVE-2015-1271", "CVE-2015-1272", "CVE-2015-1273", "CVE-2015-1274", "CVE-2015-1275", "CVE-2015-1276", "CVE-2015-1277", "CVE-2015-1278", "CVE-2015-1279", "CVE-2015-1280", "CVE-2015-1281", "CVE-2015-1282", "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1285", "CVE-2015-1286", "CVE-2015-1287", "CVE-2015-1288", "CVE-2015-1289", "CVE-2015-1290");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (9d732078-32c7-11e5-b263-00262d5ed8ee)");
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
"Google Chrome Releases reports :

43 security fixes in this release, including :

- [446032] High CVE-2015-1271: Heap-buffer-overflow in pdfium. Credit
to cloudfuzzer.

- [459215] High CVE-2015-1273: Heap-buffer-overflow in pdfium. Credit
to makosoft.

- [461858] High CVE-2015-1274: Settings allowed executable files to
run immediately after download. Credit to andrewm.bpi.

- [462843] High CVE-2015-1275: UXSS in Chrome for Android. Credit to
WangTao(neobyte) of Baidu X-Team.

- [472614] High CVE-2015-1276: Use-after-free in IndexedDB. Credit to
Collin Payne.

- [483981] High CVE-2015-1279: Heap-buffer-overflow in pdfium. Credit
to mlafon.

- [486947] High CVE-2015-1280: Memory corruption in skia. Credit to
cloudfuzzer.

- [487155] High CVE-2015-1281: CSP bypass. Credit to Masato Kinugawa.

- [487928] High CVE-2015-1282: Use-after-free in pdfium. Credit to
Chamal de Silva.

- [492052] High CVE-2015-1283: Heap-buffer-overflow in expat. Credit
to sidhpurwala.huzaifa.

- [493243] High CVE-2015-1284: Use-after-free in blink. Credit to Atte
Kettunen of OUSPG.

- [504011] High CVE-2015-1286: UXSS in blink. Credit to anonymous.

- [505374] High CVE-2015-1290: Memory corruption in V8. Credit to
Yongjun Liu of NSFOCUS Security Team.

- [419383] Medium CVE-2015-1287: SOP bypass with CSS. Credit to
filedescriptor.

- [444573] Medium CVE-2015-1270: Uninitialized memory read in ICU.
Credit to Atte Kettunen of OUSPG.

- [451456] Medium CVE-2015-1272: Use-after-free related to unexpected
GPU process termination. Credit to Chamal de Silva.

- [479743] Medium CVE-2015-1277: Use-after-free in accessibility.
Credit to SkyLined.

- [482380] Medium CVE-2015-1278: URL spoofing using pdf files. Credit
to Chamal de Silva.

- [498982] Medium CVE-2015-1285: Information leak in XSS auditor.
Credit to gazheyes.

- [479162] Low CVE-2015-1288: Spell checking dictionaries fetched over
HTTP. Credit to mike@michaelruddy.com.

- [512110] CVE-2015-1289: Various fixes from internal audits, fuzzing
and other initiatives."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://googlechromereleases.blogspot.nl/"
  );
  # http://www.freebsd.org/ports/portaudit/9d732078-32c7-11e5-b263-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38e84225"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/27");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<44.0.2403.89")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<44.0.2403.89")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<44.0.2403.89")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
