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
  script_id(57292);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/21 23:57:17 $");

  script_cve_id("CVE-2011-3903", "CVE-2011-3904", "CVE-2011-3905", "CVE-2011-3906", "CVE-2011-3907", "CVE-2011-3908", "CVE-2011-3909", "CVE-2011-3910", "CVE-2011-3911", "CVE-2011-3912", "CVE-2011-3913", "CVE-2011-3914", "CVE-2011-3915", "CVE-2011-3916", "CVE-2011-3917");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (68ac6266-25c3-11e1-b63a-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[81753] Medium CVE-2011-3903: Out-of-bounds read in regex matching.
Credit to David Holloway of the Chromium development community.
[95465] Low CVE-2011-3905: Out-of-bounds reads in libxml. Credit to
Google Chrome Security Team (Inferno). [98809] Medium CVE-2011-3906:
Out-of-bounds read in PDF parser. Credit to Aki Helin of OUSPG.
[99016] High CVE-2011-3907: URL bar spoofing with view-source. Credit
to Mitja Kolsek of ACROS Security. [100863] Low CVE-2011-3908:
Out-of-bounds read in SVG parsing. Credit to Aki Helin of OUSPG.
[101010] Medium CVE-2011-3909: [64-bit only] Memory corruption in CSS
property array. Credit to Google Chrome Security Team (scarybeasts)
and Chu. [101494] Medium CVE-2011-3910: Out-of-bounds read in YUV
video frame handling. Credit to Google Chrome Security Team (Cris
Neckar). [101779] Medium CVE-2011-3911: Out-of-bounds read in PDF.
Credit to Google Chrome Security Team (scarybeasts) and Robert Swiecki
of the Google Security Team. [102359] High CVE-2011-3912:
Use-after-free in SVG filters. Credit to Arthur Gerkis. [103921] High
CVE-2011-3913: Use-after-free in Range handling. Credit to Arthur
Gerkis. [104011] High CVE-2011-3914: Out-of-bounds write in v8 i18n
handling. Credit to Slawomir Blazek. [104529] High CVE-2011-3915:
Buffer overflow in PDF font handling. Credit to Atte Kettunen of
OUSPG. [104959] Medium CVE-2011-3916: Out-of-bounds reads in PDF cross
references. Credit to Atte Kettunen of OUSPG. [105162] Medium
CVE-2011-3917: Stack-buffer-overflow in FileWatcher. Credit to Google
Chrome Security Team (Marty Barbella). [107258] High CVE-2011-3904:
Use-after-free in bidi handling. Credit to Google Chrome Security Team
(Inferno) and miaubiz."
  );
  # http://googlechromereleases.blogspot.com/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29fa020e"
  );
  # http://www.freebsd.org/ports/portaudit/68ac6266-25c3-11e1-b63a-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51c2b178"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<16.0.912.63")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
