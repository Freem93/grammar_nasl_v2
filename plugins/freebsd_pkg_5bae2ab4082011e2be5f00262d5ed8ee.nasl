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
  script_id(62340);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/21 23:52:44 $");

  script_cve_id("CVE-2012-2874", "CVE-2012-2875", "CVE-2012-2876", "CVE-2012-2877", "CVE-2012-2878", "CVE-2012-2879", "CVE-2012-2880", "CVE-2012-2881", "CVE-2012-2882", "CVE-2012-2883", "CVE-2012-2884", "CVE-2012-2885", "CVE-2012-2886", "CVE-2012-2887", "CVE-2012-2888", "CVE-2012-2889", "CVE-2012-2890", "CVE-2012-2891", "CVE-2012-2892", "CVE-2012-2893", "CVE-2012-2894", "CVE-2012-2895");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (5bae2ab4-0820-11e2-be5f-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[143439] High CVE-2012-2889: UXSS in frame handling. Credit to Sergey
Glazunov.

[143437] High CVE-2012-2886: UXSS in v8 bindings. Credit to Sergey
Glazunov.

[139814] High CVE-2012-2881: DOM tree corruption with plug-ins. Credit
to Chamal de Silva.

[135432] High CVE-2012-2876: Buffer overflow in SSE2 optimizations.
Credit to Atte Kettunen of OUSPG.

[140803] High CVE-2012-2883: Out-of-bounds write in Skia. Credit to
Atte Kettunen of OUSPG.

[143609] High CVE-2012-2887: Use-after-free in onclick handling.
Credit to Atte Kettunen of OUSPG.

[143656] High CVE-2012-2888: Use-after-free in SVG text references.
Credit to miaubiz.

[144899] High CVE-2012-2894: Crash in graphics context handling.
Credit to Slawomir Blazek.

[137707] Medium CVE-2012-2877: Browser crash with extensions and modal
dialogs. Credit to Nir Moshe.

[139168] Low CVE-2012-2879: DOM topology corruption. Credit to pawlkt.

[141651] Medium CVE-2012-2884: Out-of-bounds read in Skia. Credit to
Atte Kettunen of OUSPG.

[132398] High CVE-2012-2874: Out-of-bounds write in Skia. Credit to
Google Chrome Security Team (Inferno).

[134955] [135488] [137106] [137288] [137302] [137547] [137556]
[137606] [137635] [137880] [137928] [144579] [145079] [145121]
[145163] [146462] Medium CVE-2012-2875: Various lower severity issues
in the PDF viewer. Credit to Mateusz Jurczyk of Google Security Team,
with contributions by Gynvael Coldwind of Google Security Team.

[137852] High CVE-2012-2878: Use-after-free in plug-in handling.
Credit to Fermin Serna of Google Security Team.

[139462] Medium CVE-2012-2880: Race condition in plug-in paint buffer.
Credit to Google Chrome Security Team (Cris Neckar).

[140647] High CVE-2012-2882: Wild pointer in OGG container handling.
Credit to Google Chrome Security Team (Inferno).

[142310] Medium CVE-2012-2885: Possible double free on exit. Credit to
the Chromium development community.

[143798] [144072] [147402] High CVE-2012-2890: Use-after-free in PDF
viewer. Credit to Mateusz Jurczyk of Google Security Team, with
contributions by Gynvael Coldwind of Google Security Team.

[144051] Low CVE-2012-2891: Address leak over IPC. Credit to Lei Zhang
of the Chromium development community.

[144704] Low CVE-2012-2892: Pop-up block bypass. Credit to Google
Chrome Security Team (Cris Neckar).

[144799] High CVE-2012-2893: Double free in XSL transforms. Credit to
Google Chrome Security Team (Cris Neckar).

[145029] [145157] [146460] High CVE-2012-2895: Out-of-bounds writes in
PDF viewer. Credit to Mateusz Jurczyk of Google Security Team, with
contributions by Gynvael Coldwind of Google Security Team."
  );
  # http://googlechromereleases.blogspot.nl/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdc75d6a"
  );
  # http://www.freebsd.org/ports/portaudit/5bae2ab4-0820-11e2-be5f-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79dca06d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<22.0.1229.79")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
