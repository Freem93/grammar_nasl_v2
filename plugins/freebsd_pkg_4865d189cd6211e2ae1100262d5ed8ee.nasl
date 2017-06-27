#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(66799);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/29 02:48:06 $");

  script_cve_id("CVE-2013-2855", "CVE-2013-2856", "CVE-2013-2857", "CVE-2013-2858", "CVE-2013-2859", "CVE-2013-2860", "CVE-2013-2861", "CVE-2013-2862", "CVE-2013-2863", "CVE-2013-2864", "CVE-2013-2865");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (4865d189-cd62-11e2-ae11-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[242322] Medium CVE-2013-2855: Memory corruption in dev tools API.
Credit to 'daniel.zulla'.

[242224] High CVE-2013-2856: Use-after-free in input handling. Credit
to miaubiz.

[240124] High CVE-2013-2857: Use-after-free in image handling. Credit
to miaubiz.

[239897] High CVE-2013-2858: Use-after-free in HTML5 Audio. Credit to
'cdel921'.

[237022] High CVE-2013-2859: Cross-origin namespace pollution. to
'bobbyholley'.

[225546] High CVE-2013-2860: Use-after-free with workers accessing
database APIs. Credit to Collin Payne.

[209604] High CVE-2013-2861: Use-after-free with SVG. Credit to
miaubiz.

[161077] High CVE-2013-2862: Memory corruption in Skia GPU handling.
Credit to Atte Kettunen of OUSPG.

[232633] Critical CVE-2013-2863: Memory corruption in SSL socket
handling. Credit to Sebastian Marchand of the Chromium development
community.

[239134] High CVE-2013-2864: Bad free in PDF viewer. Credit to Mateusz
Jurczyk, with contributions by Gynvael Coldwind, both from Google
Security Team.

[246389] High CVE-2013-2865: Various fixes from internal audits,
fuzzing and other initiatives."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://googlechromereleases.blogspot.nl/"
  );
  # http://www.freebsd.org/ports/portaudit/4865d189-cd62-11e2-ae11-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bc8e5b4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<27.0.1453.110")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
