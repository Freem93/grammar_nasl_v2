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
  script_id(65067);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/21 23:52:42 $");

  script_cve_id("CVE-2013-0902", "CVE-2013-0903", "CVE-2013-0904", "CVE-2013-0905", "CVE-2013-0906", "CVE-2013-0907", "CVE-2013-0908", "CVE-2013-0909", "CVE-2013-0910", "CVE-2013-0911");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (40d5ab37-85f2-11e2-b528-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[176882] High CVE-2013-0902: Use-after-free in frame loader. Credit to
Chamal de Silva.

[176252] High CVE-2013-0903: Use-after-free in browser navigation
handling. Credit to 'chromium.khalil'.

[172926] [172331] High CVE-2013-0904: Memory corruption in Web Audio.
Credit to Atte Kettunen of OUSPG.

[168982] High CVE-2013-0905: Use-after-free with SVG animations.
Credit to Atte Kettunen of OUSPG.

[174895] High CVE-2013-0906: Memory corruption in Indexed DB. Credit
to Google Chrome Security Team (Juri Aedla).

[174150] Medium CVE-2013-0907: Race condition in media thread
handling. Credit to Andrew Scherkus of the Chromium development
community.

[174059] Medium CVE-2013-0908: Incorrect handling of bindings for
extension processes.

[173906] Low CVE-2013-0909: Referer leakage with XSS Auditor. Credit
to Egor Homakov.

[172573] Medium CVE-2013-0910: Mediate renderer -> browser plug-in
loads more strictly. Credit to Google Chrome Security Team (Chris
Evans).

[172264] High CVE-2013-0911: Possible path traversal in database
handling. Credit to Google Chrome Security Team (Juri Aedla)."
  );
  # http://googlechromereleases.blogspot.nl/search/Stable%20Updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bd43a3e"
  );
  # http://www.freebsd.org/ports/portaudit/40d5ab37-85f2-11e2-b528-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0720a2b6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/07");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<25.0.1364.152")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
