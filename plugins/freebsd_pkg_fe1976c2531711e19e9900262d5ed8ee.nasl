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
  script_id(57883);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/22 00:15:02 $");

  script_cve_id("CVE-2011-3953", "CVE-2011-3954", "CVE-2011-3955", "CVE-2011-3956", "CVE-2011-3957", "CVE-2011-3958", "CVE-2011-3959", "CVE-2011-3960", "CVE-2011-3961", "CVE-2011-3962", "CVE-2011-3963", "CVE-2011-3964", "CVE-2011-3965", "CVE-2011-3966", "CVE-2011-3967", "CVE-2011-3968", "CVE-2011-3969", "CVE-2011-3970", "CVE-2011-3971", "CVE-2011-3972");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (fe1976c2-5317-11e1-9e99-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[73478] Low CVE-2011-3953: Avoid clipboard monitoring after paste
event. Credit to Daniel Cheng of the Chromium development community.

[92550] Low CVE-2011-3954: Crash with excessive database usage. Credit
to Collin Payne.

[93106] High CVE-2011-3955: Crash aborting an IndexDB transaction.
Credit to David Grogan of the Chromium development community.

[103630] Low CVE-2011-3956: Incorrect handling of sandboxed origins
inside extensions. Credit to Devdatta Akhawe, UC Berkeley.

[104056] High CVE-2011-3957: Use-after-free in PDF garbage collection.
Credit to Aki Helin of OUSPG.

[105459] High CVE-2011-3958: Bad casts with column spans. Credit to
miaubiz.

[106441] High CVE-2011-3959: Buffer overflow in locale handling.
Credit to Aki Helin of OUSPG.

[108416] Medium CVE-2011-3960: Out-of-bounds read in audio decoding.
Credit to Aki Helin of OUSPG.

[108871] Critical CVE-2011-3961: Race condition after crash of utility
process. Credit to Shawn Goertzen.

[108901] Medium CVE-2011-3962: Out-of-bounds read in path clipping.
Credit to Aki Helin of OUSPG.

[109094] Medium CVE-2011-3963: Out-of-bounds read in PDF fax image
handling. Credit to Atte Kettunen of OUSPG.

[109245] Low CVE-2011-3964: URL bar confusion after drag + drop.
Credit to Code Audit Labs of VulnHunt.com.

[109664] Low CVE-2011-3965: Crash in signature check. Credit to
Slawomir Blazek.

[109716] High CVE-2011-3966: Use-after-free in stylesheet error
handling. Credit to Aki Helin of OUSPG.

[109717] Low CVE-2011-3967: Crash with unusual certificate. Credit to
Ben Carrillo.

[109743] High CVE-2011-3968: Use-after-free in CSS handling. Credit to
Arthur Gerkis.

[110112] High CVE-2011-3969: Use-after-free in SVG layout. Credit to
Arthur Gerkis.

[110277] Medium CVE-2011-3970: Out-of-bounds read in libxslt. Credit
to Aki Helin of OUSPG.

[110374] High CVE-2011-3971: Use-after-free with mousemove events.
Credit to Arthur Gerkis.

[110559] Medium CVE-2011-3972: Out-of-bounds read in shader
translator. Credit to Google Chrome Security Team (Inferno)."
  );
  # http://googlechromereleases.blogspot.com/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29fa020e"
  );
  # http://www.freebsd.org/ports/portaudit/fe1976c2-5317-11e1-9e99-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b46898fd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/10");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<17.0.963.46")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
