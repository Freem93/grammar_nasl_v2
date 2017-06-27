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
  script_id(59750);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/06/22 00:15:02 $");

  script_cve_id("CVE-2012-2815", "CVE-2012-2817", "CVE-2012-2818", "CVE-2012-2819", "CVE-2012-2820", "CVE-2012-2821", "CVE-2012-2822", "CVE-2012-2823", "CVE-2012-2824", "CVE-2012-2826", "CVE-2012-2827", "CVE-2012-2828", "CVE-2012-2829", "CVE-2012-2830", "CVE-2012-2831", "CVE-2012-2832", "CVE-2012-2833", "CVE-2012-2834");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (ff922811-c096-11e1-b0f4-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[118633] Low CVE-2012-2815: Leak of iframe fragment id. Credit to Elie
Bursztein of Google.

[120222] High CVE-2012-2817: Use-after-free in table section handling.
Credit to miaubiz.

[120944] High CVE-2012-2818: Use-after-free in counter layout. Credit
to miaubiz.

[120977] High CVE-2012-2819: Crash in texture handling. Credit to Ken
'gets' Russell of the Chromium development community.

[121926] Medium CVE-2012-2820: Out-of-bounds read in SVG filter
handling. Credit to Atte Kettunen of OUSPG.

[122925] Medium CVE-2012-2821: Autofill display problem. Credit to
'simonbrown60'.

[various] Medium CVE-2012-2822: Misc. lower severity OOB read issues
in PDF. Credit to awesome ASAN and various Googlers (Kostya
Serebryany, Evgeniy Stepanov, Mateusz Jurczyk, Gynvael Coldwind).

[124356] High CVE-2012-2823: Use-after-free in SVG resource handling.
Credit to miaubiz.

[125374] High CVE-2012-2824: Use-after-free in SVG painting. Credit to
miaubiz.

[128688] Medium CVE-2012-2826: Out-of-bounds read in texture
conversion. Credit to Google Chrome Security Team (Inferno).

[Mac only] [129826] Low CVE-2012-2827: Use-after-free in Mac UI.
Credit to the Chromium development community (Dharani Govindan).

[129857] High CVE-2012-2828: Integer overflows in PDF. Credit to
Mateusz Jurczyk of Google Security Team and Google Chrome Security
Team (Chris Evans).

[129947] High CVE-2012-2829: Use-after-free in first-letter handling.
Credit to miaubiz.

[129951] High CVE-2012-2830: Wild pointer in array value setting.
Credit to miaubiz.

[130356] High CVE-2012-2831: Use-after-free in SVG reference handling.
Credit to miaubiz.

[131553] High CVE-2012-2832: Uninitialized pointer in PDF image codec.
Credit to Mateusz Jurczyk of Google Security Team.

[132156] High CVE-2012-2833: Buffer overflow in PDF JS API. Credit to
Mateusz Jurczyk of Google Security Team.

[132779] High CVE-2012-2834: Integer overflow in Matroska container.
Credit to Juri Aedla."
  );
  # http://googlechromereleases.blogspot.com/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29fa020e"
  );
  # http://www.freebsd.org/ports/portaudit/ff922811-c096-11e1-b0f4-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09fae784"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/28");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<20.0.1132.43")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
