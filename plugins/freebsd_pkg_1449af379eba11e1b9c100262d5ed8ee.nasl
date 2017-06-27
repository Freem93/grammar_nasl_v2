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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59103);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/21 23:43:35 $");

  script_cve_id("CVE-2011-3083", "CVE-2011-3084", "CVE-2011-3085", "CVE-2011-3086", "CVE-2011-3087", "CVE-2011-3088", "CVE-2011-3089", "CVE-2011-3090", "CVE-2011-3091", "CVE-2011-3092", "CVE-2011-3093", "CVE-2011-3094", "CVE-2011-3095", "CVE-2011-3096", "CVE-2011-3097", "CVE-2011-3099", "CVE-2011-3100");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (1449af37-9eba-11e1-b9c1-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[112983] Low CVE-2011-3083: Browser crash with video + FTP. Credit to
Aki Helin of OUSPG.

[113496] Low CVE-2011-3084: Load links from internal pages in their
own process. Credit to Brett Wilson of the Chromium development
community.

[118374] Medium CVE-2011-3085: UI corruption with long autofilled
values. Credit to 'psaldorn'.

[118642] High CVE-2011-3086: Use-after-free with style element. Credit
to Arthur Gerkis.

[118664] Low CVE-2011-3087: Incorrect window navigation. Credit to
Charlie Reis of the Chromium development community.

[120648] Medium CVE-2011-3088: Out-of-bounds read in hairline drawing.
Credit to Aki Helin of OUSPG.

[120711] High CVE-2011-3089: Use-after-free in table handling. Credit
to miaubiz.

[121223] Medium CVE-2011-3090: Race condition with workers. Credit to
Arthur Gerkis.

[121734] High CVE-2011-3091: Use-after-free with indexed DB. Credit to
Google Chrome Security Team (Inferno).

[122337] High CVE-2011-3092: Invalid write in v8 regex. Credit to
Christian Holler.

[122585] Medium CVE-2011-3093: Out-of-bounds read in glyph handling.
Credit to miaubiz.

[122586] Medium CVE-2011-3094: Out-of-bounds read in Tibetan handling.
Credit to miaubiz.

[123481] High CVE-2011-3095: Out-of-bounds write in OGG container.
Credit to Hannu Heikkinen.

[Linux only] [123530] Low CVE-2011-3096: Use-after-free in GTK omnibox
handling. Credit to Arthur Gerkis.

[123733] [124182] High CVE-2011-3097: Out-of-bounds write in sampled
functions with PDF. Credit to Kostya Serebryany of Google and Evgeniy
Stepanov of Google.

[124479] High CVE-2011-3099: Use-after-free in PDF with corrupt font
encoding name. Credit to Mateusz Jurczyk of Google Security Team and
Gynvael Coldwind of Google Security Team.

[124652] Medium CVE-2011-3100: Out-of-bounds read drawing dash paths.
Credit to Google Chrome Security Team (Inferno)."
  );
  # http://googlechromereleases.blogspot.com/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29fa020e"
  );
  # http://www.freebsd.org/ports/portaudit/1449af37-9eba-11e1-b9c1-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52ef9bf4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<19.0.1084.46")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
