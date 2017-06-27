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
  script_id(91370);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/19 14:02:53 $");

  script_cve_id("CVE-2016-1672", "CVE-2016-1673", "CVE-2016-1674", "CVE-2016-1675", "CVE-2016-1677", "CVE-2016-1678", "CVE-2016-1679", "CVE-2016-1680", "CVE-2016-1681", "CVE-2016-1682", "CVE-2016-1685", "CVE-2016-1686", "CVE-2016-1687", "CVE-2016-1688", "CVE-2016-1689", "CVE-2016-1690", "CVE-2016-1691", "CVE-2016-1692", "CVE-2016-1693", "CVE-2016-1694", "CVE-2016-1695");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (1a6bbb95-24b8-11e6-bd31-3065ec8fd3ec)");
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

42 security fixes in this release, including :

- [590118] High CVE-2016-1672: Cross-origin bypass in extension
bindings. Credit to Mariusz Mlynski.

- [597532] High CVE-2016-1673: Cross-origin bypass in Blink. Credit to
Mariusz Mlynski.

- [598165] High CVE-2016-1674: Cross-origin bypass in extensions.i
Credit to Mariusz Mlynski.

- [600182] High CVE-2016-1675: Cross-origin bypass in Blink. Credit to
Mariusz Mlynski.

- [604901] High CVE-2016-1676: Cross-origin bypass in extension
bindings. Credit to Rob Wu.

- [602970] Medium CVE-2016-1677: Type confusion in V8. Credit to Guang
Gong of Qihoo 360.

- [595259] High CVE-2016-1678: Heap overflow in V8. Credit to
Christian Holler.

- [606390] High CVE-2016-1679: Heap use-after-free in V8 bindings.
Credit to Rob Wu.

- [589848] High CVE-2016-1680: Heap use-after-free in Skia. Credit to
Atte Kettunen of OUSPG.

- [613160] High CVE-2016-1681: Heap overflow in PDFium. Credit to
Aleksandar Nikolic of Cisco Talos.

- [579801] Medium CVE-2016-1682: CSP bypass for ServiceWorker. Credit
to KingstonTime.

- [601362] Medium CVE-2016-1685: Out-of-bounds read in PDFium. Credit
to Ke Liu of Tencent's Xuanwu LAB.

- [603518] Medium CVE-2016-1686: Out-of-bounds read in PDFium. Credit
to Ke Liu of Tencent's Xuanwu LAB.

- [603748] Medium CVE-2016-1687: Information leak in extensions.
Credit to Rob Wu.

- [604897] Medium CVE-2016-1688: Out-of-bounds read in V8. Credit to
Max Korenko.

- [606185] Medium CVE-2016-1689: Heap buffer overflow in media. Credit
to Atte Kettunen of OUSPG.

- [608100] Medium CVE-2016-1690: Heap use-after-free in Autofill.
Credit to Rob Wu.

- [597926] Low CVE-2016-1691: Heap buffer-overflow in Skia. Credit to
Atte Kettunen of OUSPG.

- [598077] Low CVE-2016-1692: Limited cross-origin bypass in
ServiceWorker. Credit to Til Jasper Ullrich.

- [598752] Low CVE-2016-1693: HTTP Download of Software Removal Tool.
Credit to Khalil Zhani.

- [603682] Low CVE-2016-1694: HPKP pins removed on cache clearance.
Credit to Ryan Lester and Bryant Zadegan.

- [614767] CVE-2016-1695: Various fixes from internal audits, fuzzing
and other initiatives."
  );
  # http://googlechromereleases.blogspot.nl/2016/05/stable-channel-update_25.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1546e55e"
  );
  # http://www.freebsd.org/ports/portaudit/1a6bbb95-24b8-11e6-bd31-3065ec8fd3ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?225606ac"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/31");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<51.0.2704.63")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<51.0.2704.63")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<51.0.2704.63")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
