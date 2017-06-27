#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
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
  script_id(83556);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/06/28 04:36:42 $");

  script_cve_id("CVE-2015-1251", "CVE-2015-1252", "CVE-2015-1253", "CVE-2015-1254", "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258", "CVE-2015-1259", "CVE-2015-1260", "CVE-2015-1261", "CVE-2015-1262", "CVE-2015-1263", "CVE-2015-1264", "CVE-2015-1265");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (a9d456b4-fe4c-11e4-ad15-00262d5ed8ee)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

37 security fixes in this release, including :

- [474029] High CVE-2015-1252: Sandbox escape in Chrome. Credit to
anonymous.

- [464552] High CVE-2015-1253: Cross-origin bypass in DOM. Credit to
anonymous.

- [444927] High CVE-2015-1254: Cross-origin bypass in Editing. Credit
to armin@rawsec.net.

- [473253] High CVE-2015-1255: Use-after-free in WebAudio. Credit to
Khalil Zhani.

- [478549] High CVE-2015-1256: Use-after-free in SVG. Credit to Atte
Kettunen of OUSPG.

- [481015] High CVE-2015-1251: Use-after-free in Speech. Credit to
SkyLined working with HP's Zero Day Initiative.

- [468519] Medium CVE-2015-1257: Container-overflow in SVG. Credit to
miaubiz.

- [450939] Medium CVE-2015-1258: Negative-size parameter in libvpx.
Credit to cloudfuzzer

- [468167] Medium CVE-2015-1259: Uninitialized value in PDFium. Credit
to Atte Kettunen of OUSPG

- [474370] Medium CVE-2015-1260: Use-after-free in WebRTC. Credit to
Khalil Zhani.

- [466351] Medium CVE-2015-1261: URL bar spoofing. Credit to Juho
Nurminen.

- [476647] Medium CVE-2015-1262: Uninitialized value in Blink. Credit
to miaubiz.

- [479162] Low CVE-2015-1263: Insecure download of spellcheck
dictionary. Credit to Mike Ruddy.

- [481015] Low CVE-2015-1264: Cross-site scripting in bookmarks.
Credit to K0r3Ph1L.

- [489518] CVE-2015-1265: Various fixes from internal audits, fuzzing
and other initiatives.

- Multiple vulnerabilities in V8 fixed at the tip of the 4.3 branch
(currently 4.3.61.21)."
  );
  # http://googlechromereleases.blogspot.nl/2015/05/stable-channel-update_19.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73e36afd"
  );
  # http://www.freebsd.org/ports/portaudit/a9d456b4-fe4c-11e4-ad15-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ae7cf35"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<43.0.2357.65")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<43.0.2357.65")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<43.0.2357.65")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
