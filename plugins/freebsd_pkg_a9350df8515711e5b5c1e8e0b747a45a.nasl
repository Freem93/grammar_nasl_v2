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

include("compat.inc");

if (description)
{
  script_id(85758);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2015/10/04 04:38:26 $");

  script_cve_id("CVE-2015-1291", "CVE-2015-1292", "CVE-2015-1293", "CVE-2015-1294", "CVE-2015-1295", "CVE-2015-1296", "CVE-2015-1297", "CVE-2015-1298", "CVE-2015-1299", "CVE-2015-1300", "CVE-2015-1301");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (a9350df8-5157-11e5-b5c1-e8e0b747a45a)");
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

29 security fixes in this release, including :

- [516377] High CVE-2015-1291: Cross-origin bypass in DOM. Credit to
anonymous.

- [522791] High CVE-2015-1292: Cross-origin bypass in ServiceWorker.
Credit to Mariusz Mlynski.

- [524074] High CVE-2015-1293: Cross-origin bypass in DOM. Credit to
Mariusz Mlynski.

- [492263] High CVE-2015-1294: Use-after-free in Skia. Credit to
cloudfuzzer.

- [502562] High CVE-2015-1295: Use-after-free in Printing. Credit to
anonymous.

- [421332] High CVE-2015-1296: Character spoofing in omnibox. Credit
to zcorpan.

- [510802] Medium CVE-2015-1297: Permission scoping error in
Webrequest. Credit to Alexander Kashev.

- [518827] Medium CVE-2015-1298: URL validation error in extensions.
Credit to Rob Wu.

- [416362] Medium CVE-2015-1299: Use-after-free in Blink. Credit to
taro.suzuki.dev.

- [511616] Medium CVE-2015-1300: Information leak in Blink. Credit to
cgvwzq.

- [526825] CVE-2015-1301: Various fixes from internal audits, fuzzing
and other initiatives."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://googlechromereleases.blogspot.nl"
  );
  # http://www.freebsd.org/ports/portaudit/a9350df8-5157-11e5-b5c1-e8e0b747a45a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?506a494f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<45.0.2454.85")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<45.0.2454.85")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<45.0.2454.85")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
