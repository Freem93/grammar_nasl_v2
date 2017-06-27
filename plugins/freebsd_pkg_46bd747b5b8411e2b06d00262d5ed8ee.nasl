#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
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
  script_id(63469);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 16:04:31 $");

  script_cve_id("CVE-2012-5145", "CVE-2012-5146", "CVE-2012-5147", "CVE-2012-5148", "CVE-2012-5149", "CVE-2012-5150", "CVE-2012-5151", "CVE-2012-5152", "CVE-2012-5153", "CVE-2012-5155", "CVE-2012-5156", "CVE-2012-5157", "CVE-2013-0828", "CVE-2013-0829", "CVE-2013-0831", "CVE-2013-0832", "CVE-2013-0833", "CVE-2013-0834", "CVE-2013-0835", "CVE-2013-0836", "CVE-2013-0837", "CVE-2013-0838");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (46bd747b-5b84-11e2-b06d-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[162494] High CVE-2012-5145: Use-after-free in SVG layout. Credit to
Atte Kettunen of OUSPG.

[165622] High CVE-2012-5146: Same origin policy bypass with malformed
URL. Credit to Erling A Ellingsen and Subodh Iyengar, both of
Facebook.

[165864] High CVE-2012-5147: Use-after-free in DOM handling. Credit to
Jose A. Vazquez.

[167122] Medium CVE-2012-5148: Missing filename sanitization in
hyphenation support. Credit to Google Chrome Security Team (Justin
Schuh).

[166795] High CVE-2012-5149: Integer overflow in audio IPC handling.
Credit to Google Chrome Security Team (Chris Evans).

[165601] High CVE-2012-5150: Use-after-free when seeking video. Credit
to Google Chrome Security Team (Inferno).

[165538] High CVE-2012-5151: Integer overflow in PDF JavaScript.
Credit to Mateusz Jurczyk, with contribution from Gynvael Coldwind,
both of Google Security Team.

[165430] Medium CVE-2012-5152: Out-of-bounds read when seeking video.
Credit to Google Chrome Security Team (Inferno).

[164565] High CVE-2012-5153: Out-of-bounds stack access in v8. Credit
to Andreas Rossberg of the Chromium development community.

[Mac only] [163208] Medium CVE-2012-5155: Missing Mac sandbox for
worker processes. Credit to Google Chrome Security Team (Julien
Tinnes).

[162778] High CVE-2012-5156: Use-after-free in PDF fields. Credit to
Mateusz Jurczyk, with contribution from Gynvael Coldwind, both of
Google Security Team.

[162776] [162156] Medium CVE-2012-5157: Out-of-bounds reads in PDF
image handling. Credit to Mateusz Jurczyk, with contribution from
Gynvael Coldwind, both of Google Security Team.

[162153] High CVE-2013-0828: Bad cast in PDF root handling. Credit to
Mateusz Jurczyk, with contribution from Gynvael Coldwind, both of
Google Security Team.

[162114] High CVE-2013-0829: Corruption of database metadata leading
to incorrect file access. Credit to Google Chrome Security Team (Juri
Aedla).

[161836] Low CVE-2013-0831: Possible path traversal from extension
process. Credit to Google Chrome Security Team (Tom Sepez).

[160380] Medium CVE-2013-0832: Use-after-free with printing. Credit to
Google Chrome Security Team (Cris Neckar).

[154485] Medium CVE-2013-0833: Out-of-bounds read with printing.
Credit to Google Chrome Security Team (Cris Neckar).

[154283] Medium CVE-2013-0834: Out-of-bounds read with glyph handling.
Credit to Google Chrome Security Team (Cris Neckar).

[152921] Low CVE-2013-0835: Browser crash with geolocation. Credit to
Arthur Gerkis.

[150545] High CVE-2013-0836: Crash in v8 garbage collection. Credit to
Google Chrome Security Team (Cris Neckar).

[145363] Medium CVE-2013-0837: Crash in extension tab handling. Credit
to Tom Nielsen.

[Linux only] [143859] Low CVE-2013-0838: Tighten permissions on shared
memory segments. Credit to Google Chrome Security Team (Chris Palmer)."
  );
  # http://googlechromereleases.blogspot.nl/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdc75d6a"
  );
  # http://www.freebsd.org/ports/portaudit/46bd747b-5b84-11e2-b06d-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d83e3b4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<24.0.1312.52")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
