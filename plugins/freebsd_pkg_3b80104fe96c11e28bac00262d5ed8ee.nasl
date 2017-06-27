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
  script_id(67237);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/26 05:42:54 $");

  script_cve_id("CVE-2013-2853", "CVE-2013-2867", "CVE-2013-2868", "CVE-2013-2869", "CVE-2013-2870", "CVE-2013-2871", "CVE-2013-2872", "CVE-2013-2873", "CVE-2013-2875", "CVE-2013-2876", "CVE-2013-2877", "CVE-2013-2878", "CVE-2013-2879");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (3b80104f-e96c-11e2-8bac-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

A special reward for Andrey Labunets for his combination of
CVE-2013-2879 and CVE-2013-2868 along with some (since fixed)
server-side bugs.

[252216] Low CVE-2013-2867: Block pop-unders in various scenarios.

[252062] High CVE-2013-2879: Confusion setting up sign-in and sync.
Credit to Andrey Labunets.

[252034] Medium CVE-2013-2868: Incorrect sync of NPAPI extension
component. Credit to Andrey Labunets.

[245153] Medium CVE-2013-2869: Out-of-bounds read in JPEG2000
handling. Credit to Felix Groebert of Google Security Team.

[244746] [242762] Critical CVE-2013-2870: Use-after-free with network
sockets. Credit to Collin Payne.

[244260] Medium CVE-2013-2853: Man-in-the-middle attack against HTTP
in SSL. Credit to Antoine Delignat-Lavaud and Karthikeyan Bhargavan
from Prosecco at INRIA Paris.

[243991] [243818] High CVE-2013-2871: Use-after-free in input
handling. Credit to miaubiz.

[Mac only] [242702] Low CVE-2013-2872: Possible lack of entropy in
renderers. Credit to Eric Rescorla.

[241139] High CVE-2013-2873: Use-after-free in resource loading.
Credit to miaubiz.

[233848] Medium CVE-2013-2875: Out-of-bounds-read in SVG. Credit to
miaubiz.

[229504] Medium CVE-2013-2876: Extensions permissions confusion with
interstitials. Credit to Dev Akhawe.

[229019] Low CVE-2013-2877: Out-of-bounds read in XML parsing. Credit
to Aki Helin of OUSPG.

[196636] None: Remove the 'viewsource' attribute on iframes. Credit to
Collin Jackson.

[177197] Medium CVE-2013-2878: Out-of-bounds read in text handling.
Credit to Atte Kettunen of OUSPG."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://googlechromereleases.blogspot.nl/"
  );
  # http://www.freebsd.org/ports/portaudit/3b80104f-e96c-11e2-8bac-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6523f6c3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<28.0.1500.71")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
