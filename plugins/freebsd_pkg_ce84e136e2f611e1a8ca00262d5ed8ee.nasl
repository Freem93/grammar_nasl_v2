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
  script_id(61505);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/06/22 00:10:43 $");

  script_cve_id("CVE-2012-2846", "CVE-2012-2847", "CVE-2012-2848", "CVE-2012-2849", "CVE-2012-2850", "CVE-2012-2851", "CVE-2012-2852", "CVE-2012-2853", "CVE-2012-2854", "CVE-2012-2855", "CVE-2012-2856", "CVE-2012-2857", "CVE-2012-2858", "CVE-2012-2859", "CVE-2012-2860");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (ce84e136-e2f6-11e1-a8ca-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[Linux only] [125225] Medium CVE-2012-2846: Cross-process interference
in renderers. Credit to Google Chrome Security Team (Julien Tinnes).

[127522] Low CVE-2012-2847: Missing re-prompt to user upon excessive
downloads. Credit to Matt Austin of Aspect Security.

[127525] Medium CVE-2012-2848: Overly broad file access granted after
drag+drop. Credit to Matt Austin of Aspect Security.

[128163] Low CVE-2012-2849: Off-by-one read in GIF decoder. Credit to
Atte Kettunen of OUSPG.

[130251] [130592] [130611] [131068] [131237] [131252] [131621]
[131690] [132860] Medium CVE-2012-2850: Various lower severity issues
in the PDF viewer. Credit to Mateusz Jurczyk of Google Security Team,
with contributions by Gynvael Coldwind of Google Security Team.

[132585] [132694] [132861] High CVE-2012-2851: Integer overflows in
PDF viewer. Credit to Mateusz Jurczyk of Google Security Team, with
contributions by Gynvael Coldwind of Google Security Team.

[134028] High CVE-2012-2852: Use-after-free with bad object linkage in
PDF. Credit to Alexey Samsonov of Google.

[134101] Medium CVE-2012-2853: webRequest can interfere with the
Chrome Web Store. Credit to Trev of Adblock.

[134519] Low CVE-2012-2854: Leak of pointer values to WebUI renderers.
Credit to Nasko Oskov of the Chromium development community.

[134888] High CVE-2012-2855: Use-after-free in PDF viewer. Credit to
Mateusz Jurczyk of Google Security Team, with contributions by Gynvael
Coldwind of Google Security Team.

[134954] [135264] High CVE-2012-2856: Out-of-bounds writes in PDF
viewer. Credit to Mateusz Jurczyk of Google Security Team, with
contributions by Gynvael Coldwind of Google Security Team.

[136235] High CVE-2012-2857: Use-after-free in CSS DOM. Credit to
Arthur Gerkis.

[136894] High CVE-2012-2858: Buffer overflow in WebP decoder. Credit
to Juri Aedla.

[Linux only] [137541] Critical CVE-2012-2859: Crash in tab handling.
Credit to Jeff Roberts of Google Security Team.

[137671] Medium CVE-2012-2860: Out-of-bounds access when clicking in
date picker. Credit to Chamal de Silva."
  );
  # http://googlechromereleases.blogspot.com/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29fa020e"
  );
  # http://www.freebsd.org/ports/portaudit/ce84e136-e2f6-11e1-a8ca-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b33e0725"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/13");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<21.0.1180.60")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
