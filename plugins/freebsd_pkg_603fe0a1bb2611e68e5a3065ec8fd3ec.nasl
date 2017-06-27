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
  script_id(95546);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id("CVE-2016-5203", "CVE-2016-5204", "CVE-2016-5205", "CVE-2016-5206", "CVE-2016-5207", "CVE-2016-5208", "CVE-2016-5209", "CVE-2016-5210", "CVE-2016-5211", "CVE-2016-5212", "CVE-2016-5213", "CVE-2016-5214", "CVE-2016-5215", "CVE-2016-5216", "CVE-2016-5217", "CVE-2016-5218", "CVE-2016-5219", "CVE-2016-5220", "CVE-2016-5221", "CVE-2016-5222", "CVE-2016-5223", "CVE-2016-5224", "CVE-2016-5225", "CVE-2016-5226", "CVE-2016-9650", "CVE-2016-9651", "CVE-2016-9652");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (603fe0a1-bb26-11e6-8e5a-3065ec8fd3ec)");
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

36 security fixes in this release, including :

- [664411] High CVE-2016-9651: Private property access in V8. Credit
to Guang Gong of Alpha Team Of Qihoo 360

- [658535] High CVE-2016-5208: Universal XSS in Blink. Credit to
Mariusz Mlynski

- [655904] High CVE-2016-5207: Universal XSS in Blink. Credit to
Mariusz Mlynski

- [653749] High CVE-2016-5206: Same-origin bypass in PDFium. Credit to
Rob Wu (robwu.nl)

- [646610] High CVE-2016-5205: Universal XSS in Blink. Credit to
Anonymous

- [630870] High CVE-2016-5204: Universal XSS in Blink. Credit to
Mariusz Mlynski

- [664139] High CVE-2016-5209: Out of bounds write in Blink. Credit to
Giwan Go of STEALIEN

- [644219] High CVE-2016-5203: Use after free in PDFium. Credit to
Anonymous

- [654183] High CVE-2016-5210: Out of bounds write in PDFium. Credit
to Ke Liu of Tencent's Xuanwu LAB

- [653134] High CVE-2016-5212: Local file disclosure in DevTools.
Credit to Khalil Zhani

- [649229] High CVE-2016-5211: Use after free in PDFium. Credit to
Anonymous

- [652548] High CVE-2016-5213: Use after free in V8. Credit to Khalil
Zhani

- [601538] Medium CVE-2016-5214: File download protection bypass.
Credit to Jonathan Birch and MSVR

- [653090] Medium CVE-2016-5216: Use after free in PDFium. Credit to
Anonymous

- [619463] Medium CVE-2016-5215: Use after free in Webaudio. Credit to
Looben Yang

- [654280] Medium CVE-2016-5217: Use of unvalidated data in PDFium.
Credit to Rob Wu (robwu.nl)

- [660498] Medium CVE-2016-5218: Address spoofing in Omnibox. Credit
to Abdulrahman Alqabandi (@qab)

- [657568] Medium CVE-2016-5219: Use after free in V8. Credit to Rob
Wu (robwu.nl)

- [660854] Medium CVE-2016-5221: Integer overflow in ANGLE. Credit to
Tim Becker of ForAllSecure

- [654279] Medium CVE-2016-5220: Local file access in PDFium. Credit
to Rob Wu (robwu.nl)

- [657720] Medium CVE-2016-5222: Address spoofing in Omnibox. Credit
to xisigr of Tencent's Xuanwu Lab

- [653034] Low CVE-2016-9650: CSP Referrer disclosure. Credit to Jakub
Zoczek

- [652038] Low CVE-2016-5223: Integer overflow in PDFium. Credit to
Hwiwon Lee

- [639750] Low CVE-2016-5226: Limited XSS in Blink. Credit to Jun
Kokatsu (@shhnjk)

- [630332] Low CVE-2016-5225: CSP bypass in Blink. Credit to Scott
Helme (@Scott_Helme, scotthelme.co.uk)

- [615851] Low CVE-2016-5224: Same-origin bypass in SVG. Credit to
Roeland Krak

- [669928] CVE-2016-9652: Various fixes from internal audits, fuzzing
and other initiatives"
  );
  # https://googlechromereleases.blogspot.nl/2016/12/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c43db9d"
  );
  # http://www.freebsd.org/ports/portaudit/603fe0a1-bb26-11e6-8e5a-3065ec8fd3ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f45e6194"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<55.0.2883.75")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<55.0.2883.75")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<55.0.2883.75")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
