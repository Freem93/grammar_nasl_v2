#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(79320);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/12/14 06:22:30 $");

  script_cve_id("CVE-2014-0574", "CVE-2014-7899", "CVE-2014-7900", "CVE-2014-7901", "CVE-2014-7902", "CVE-2014-7903", "CVE-2014-7904", "CVE-2014-7905", "CVE-2014-7906", "CVE-2014-7907", "CVE-2014-7908", "CVE-2014-7909", "CVE-2014-7910");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (d395e44f-6f4f-11e4-a444-00262d5ed8ee)");
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

- [389734] High CVE-2014-7899: Address bar spoofing. Credit to Eli
Grey.

- [406868] High CVE-2014-7900: Use-after-free in pdfium. Credit to
Atte Kettunen from OUSPG.

- [413375] High CVE-2014-7901: Integer overflow in pdfium. Credit to
cloudfuzzer.

- [414504] High CVE-2014-7902: Use-after-free in pdfium. Credit to
cloudfuzzer.

- [414525] High CVE-2014-7903: Buffer overflow in pdfium. Credit to
cloudfuzzer.

- [418161] High CVE-2014-7904: Buffer overflow in Skia. Credit to Atte
Kettunen from OUSPG.

- [421817] High CVE-2014-7905: Flaw allowing navigation to intents
that do not have the BROWSABLE category. Credit to WangTao(neobyte) of
Baidu X-Team.

- [423030] High CVE-2014-7906: Use-after-free in pepper plugins.
Credit to Chen Zhang (demi6od) of the NSFOCUS Security Team.

- [423703] High CVE-2014-0574: Double-free in Flash. Credit to
biloulehibou.

- [424453] High CVE-2014-7907: Use-after-free in blink. Credit to Chen
Zhang (demi6od) of the NSFOCUS Security Team.

- [425980] High CVE-2014-7908: Integer overflow in media. Credit to
Christoph Diehl.

- [391001] Medium CVE-2014-7909: Uninitialized memory read in Skia.
Credit to miaubiz.

- CVE-2014-7910: Various fixes from internal audits, fuzzing and other
initiatives."
  );
  # http://googlechromereleases.blogspot.nl/2014/11/stable-channel-update_18.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4b30c17"
  );
  # http://www.freebsd.org/ports/portaudit/d395e44f-6f4f-11e4-a444-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2afe019"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<39.0.2171.65")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<39.0.2171.65")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
