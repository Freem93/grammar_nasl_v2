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
  script_id(57968);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/21 23:48:18 $");

  script_cve_id("CVE-2011-3015", "CVE-2011-3016", "CVE-2011-3017", "CVE-2011-3018", "CVE-2011-3019", "CVE-2011-3020", "CVE-2011-3021", "CVE-2011-3022", "CVE-2011-3023", "CVE-2011-3024", "CVE-2011-3025", "CVE-2011-3026", "CVE-2011-3027");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (2f5ff968-5829-11e1-8288-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[105803] High CVE-2011-3015: Integer overflows in PDF codecs. Credit
to Google Chrome Security Team (scarybeasts).

[106336] Medium CVE-2011-3016: Read-after-free with counter nodes.
Credit to miaubiz.

[108695] High CVE-2011-3017: Possible use-after-free in database
handling. Credit to miaubiz.

[110172] High CVE-2011-3018: Heap overflow in path rendering. Credit
to Aki Helin of OUSPG.

[110849] High CVE-2011-3019: Heap buffer overflow in MKV handling.
Credit to Google Chrome Security Team (scarybeasts) and Mateusz
Jurczyk of the Google Security Team.

[111575] Medium CVE-2011-3020: Native client validator error. Credit
to Nick Bray of the Chromium development community.

[111779] High CVE-2011-3021: Use-after-free in subframe loading.
Credit to Arthur Gerkis.

[112236] Medium CVE-2011-3022: Inappropriate use of http for
translation script. Credit to Google Chrome Security Team (Jorge
Obes).

[112259] Medium CVE-2011-3023: Use-after-free with drag and drop.
Credit to pa_kt.

[112451] Low CVE-2011-3024: Browser crash with empty x509 certificate.
Credit to chrometot.

[112670] Medium CVE-2011-3025: Out-of-bounds read in h.264 parsing.
Credit to Slawomir Blazek.

[112822] High CVE-2011-3026: Integer overflow / truncation in libpng.
Credit to Juri Aedla.

[112847] Medium CVE-2011-3027: Bad cast in column handling. Credit to
miaubiz."
  );
  # http://googlechromereleases.blogspot.com/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29fa020e"
  );
  # http://www.freebsd.org/ports/portaudit/2f5ff968-5829-11e1-8288-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?758fd594"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<17.0.963.56")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
