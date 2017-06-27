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
  script_id(59281);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/06/21 23:48:17 $");

  script_cve_id("CVE-2011-3103", "CVE-2011-3104", "CVE-2011-3105", "CVE-2011-3106", "CVE-2011-3107", "CVE-2011-3108", "CVE-2011-3110", "CVE-2011-3111", "CVE-2011-3112", "CVE-2011-3113", "CVE-2011-3114", "CVE-2011-3115");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (219d0bfd-a915-11e1-b519-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[117409] High CVE-2011-3103: Crashes in v8 garbage collection. Credit
to the Chromium development community (Brett Wilson).

[118018] Medium CVE-2011-3104: Out-of-bounds read in Skia. Credit to
Google Chrome Security Team (Inferno).

[120912] High CVE-2011-3105: Use-after-free in first-letter handling.
Credit to miaubiz.

[122654] Critical CVE-2011-3106: Browser memory corruption with
websockets over SSL. Credit to the Chromium development community
(Dharani Govindan).

[124625] High CVE-2011-3107: Crashes in the plug-in JavaScript
bindings. Credit to the Chromium development community (Dharani
Govindan).

[125159] Critical CVE-2011-3108: Use-after-free in browser cache.
Credit to 'efbiaiinzinz'.

[Linux only] [126296] High CVE-2011-3109: Bad cast in GTK UI. Credit
to Micha Bartholome.

[126337] [126343] [126378] [127349] [127819] [127868] High
CVE-2011-3110: Out of bounds writes in PDF. Credit to Mateusz Jurczyk
of the Google Security Team, with contributions by Gynvael Coldwind of
the Google Security Team.

[126414] Medium CVE-2011-3111: Invalid read in v8. Credit to Christian
Holler.

[127331] High CVE-2011-3112: Use-after-free with invalid encrypted
PDF. Credit to Mateusz Jurczyk of the Google Security Team, with
contributions by Gynvael Coldwind of the Google Security Team.

[127883] High CVE-2011-3113: Invalid cast with colorspace handling in
PDF. Credit to Mateusz Jurczyk of the Google Security Team, with
contributions by Gynvael Coldwind of the Google Security Team.

[128014] High CVE-2011-3114: Buffer overflows with PDF functions.
Credit to Google Chrome Security Team (scarybeasts).

[128018] High CVE-2011-3115: Type corruption in v8. Credit to
Christian Holler."
  );
  # http://googlechromereleases.blogspot.com/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29fa020e"
  );
  # http://www.freebsd.org/ports/portaudit/219d0bfd-a915-11e1-b519-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a001d350"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/29");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<19.0.1084.52")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
