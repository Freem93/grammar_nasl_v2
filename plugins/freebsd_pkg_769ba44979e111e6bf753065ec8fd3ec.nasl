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
  script_id(93495);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:02:54 $");

  script_cve_id("CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150", "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154", "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-5160", "CVE-2016-5161", "CVE-2016-5162", "CVE-2016-5163", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166", "CVE-2016-5167");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (769ba449-79e1-11e6-bf75-3065ec8fd3ec)");
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

33 security fixes in this release, including :

- [628942] High CVE-2016-5147: Universal XSS in Blink. Credit to
anonymous

- [621362] High CVE-2016-5148: Universal XSS in Blink. Credit to
anonymous

- [573131] High CVE-2016-5149: Script injection in extensions. Credit
to Max Justicz (http://web.mit.edu/maxj/www/)

- [637963] High CVE-2016-5150: Use after free in Blink. Credit to
anonymous

- [634716] High CVE-2016-5151: Use after free in PDFium. Credit to
anonymous

- [629919] High CVE-2016-5152: Heap overflow in PDFium. Credit to
GiWan Go of Stealien

- [631052] High CVE-2016-5153: Use after destruction in Blink. Credit
to Atte Kettunen of OUSPG

- [633002] High CVE-2016-5154: Heap overflow in PDFium. Credit to
anonymous

- [630662] High CVE-2016-5155: Address bar spoofing. Credit to
anonymous

- [625404] High CVE-2016-5156: Use after free in event bindings.
Credit to jinmo123

- [632622] High CVE-2016-5157: Heap overflow in PDFium. Credit to
anonymous

- [628890] High CVE-2016-5158: Heap overflow in PDFium. Credit to
GiWan Go of Stealien

- [628304] High CVE-2016-5159: Heap overflow in PDFium. Credit to
GiWan Go of Stealien

- [622420] Medium CVE-2016-5161: Type confusion in Blink. Credit to
62600BCA031B9EB5CB4A74ADDDD6771E working with Trend Micro's Zero Day
Initiative

- [589237] Medium CVE-2016-5162: Extensions web accessible resources
bypass. Credit to Nicolas Golubovic

- [609680] Medium CVE-2016-5163: Address bar spoofing. Credit to Rafay
Baloch PTCL Etisalat (http://rafayhackingarticles.net)

- [637594] Medium CVE-2016-5164: Universal XSS using DevTools. Credit
to anonymous

- [618037] Medium CVE-2016-5165: Script injection in DevTools. Credit
to Gregory Panakkal

- [616429] Medium CVE-2016-5166: SMB Relay Attack via Save Page As.
Credit to Gregory Panakkal

- [576867] Low CVE-2016-5160: Extensions web accessible resources
bypass. Credit to @l33terally, FogMarks.com (@FogMarks)

- [642598] CVE-2016-5167: Various fixes from internal audits, fuzzing
and other initiatives."
  );
  # https://googlechromereleases.blogspot.nl/2016/08/stable-channel-update-for-desktop_31.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5d87a48"
  );
  # http://www.freebsd.org/ports/portaudit/769ba449-79e1-11e6-bf75-3065ec8fd3ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5b47b4e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<53.0.2785.92")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<53.0.2785.92")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<53.0.2785.92")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
