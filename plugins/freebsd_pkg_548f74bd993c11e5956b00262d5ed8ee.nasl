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
  script_id(87177);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/05/26 16:04:31 $");

  script_cve_id("CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6769", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6774", "CVE-2015-6775", "CVE-2015-6776", "CVE-2015-6777", "CVE-2015-6778", "CVE-2015-6779", "CVE-2015-6780", "CVE-2015-6781", "CVE-2015-6782", "CVE-2015-6783", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786", "CVE-2015-6787");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (548f74bd-993c-11e5-956b-00262d5ed8ee)");
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

41 security fixes in this release, inclduding :

- [558589] Critical CVE-2015-6765: Use-after-free in AppCache. Credit
to anonymous.

- [551044] High CVE-2015-6766: Use-after-free in AppCache. Credit to
anonymous.

- [554908] High CVE-2015-6767: Use-after-free in AppCache. Credit to
anonymous.

- [556724] High CVE-2015-6768: Cross-origin bypass in DOM. Credit to
Mariusz Mlynski.

- [534923] High CVE-2015-6769: Cross-origin bypass in core. Credit to
Mariusz Mlynski.

- [541206] High CVE-2015-6770: Cross-origin bypass in DOM. Credit to
Mariusz Mlynski.

- [544991] High CVE-2015-6771: Out of bounds access in v8. Credit to
anonymous.

- [546545] High CVE-2015-6772: Cross-origin bypass in DOM. Credit to
Mariusz Mlynski.

- [554946] High CVE-2015-6764: Out of bounds access in v8. Credit to
Guang Gong of Qihoo 360 via pwn2own.

- [491660] High CVE-2015-6773: Out of bounds access in Skia. Credit to
cloudfuzzer.

- [549251] High CVE-2015-6774: Use-after-free in Extensions. Credit to
anonymous.

- [529012] High CVE-2015-6775: Type confusion in PDFium. Credit to
Atte Kettunen of OUSPG.

- [457480] High CVE-2015-6776: Out of bounds access in PDFium. Credit
to Hanno Bock.

- [544020] High CVE-2015-6777: Use-after-free in DOM. Credit to Long
Liu of Qihoo 360Vulcan Team.

- [514891] Medium CVE-2015-6778: Out of bounds access in PDFium.
Credit to Karl Skomski.

- [528505] Medium CVE-2015-6779: Scheme bypass in PDFium. Credit to
Til Jasper Ullrich.

- [490492] Medium CVE-2015-6780: Use-after-free in Infobars. Credit to
Khalil Zhani.

- [497302] Medium CVE-2015-6781: Integer overflow in Sfntly. Credit to
miaubiz.

- [536652] Medium CVE-2015-6782: Content spoofing in Omnibox. Credit
to Luan Herrera.

- [537205] Medium CVE-2015-6783: Signature validation issue in Android
Crazy Linker. Credit to Michal Bednarski.

- [503217] Low CVE-2015-6784: Escaping issue in saved pages. Credit to
Inti De Ceukelaire.

- [534542] Low CVE-2015-6785: Wildcard matching issue in CSP. Credit
to Michael Ficarra / Shape Security.

- [534570] Low CVE-2015-6786: Scheme bypass in CSP. Credit to Michael
Ficarra / Shape Security.

- [563930] CVE-2015-6787: Various fixes from internal audits, fuzzing
and other initiatives.

- Multiple vulnerabilities in V8 fixed at the tip of the 4.7 branch
(currently 4.7.80.23)."
  );
  # http://googlechromereleases.blogspot.nl/2015/12/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc8c7b02"
  );
  # http://www.freebsd.org/ports/portaudit/548f74bd-993c-11e5-956b-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eeb4ee45"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/03");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<47.0.2526.73")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<47.0.2526.73")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<47.0.2526.73")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
