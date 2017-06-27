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
  script_id(64859);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 16:04:31 $");

  script_cve_id("CVE-2013-0879", "CVE-2013-0880", "CVE-2013-0881", "CVE-2013-0882", "CVE-2013-0883", "CVE-2013-0884", "CVE-2013-0885", "CVE-2013-0887", "CVE-2013-0888", "CVE-2013-0889", "CVE-2013-0890", "CVE-2013-0891", "CVE-2013-0892", "CVE-2013-0893", "CVE-2013-0894", "CVE-2013-0895", "CVE-2013-0896", "CVE-2013-0897", "CVE-2013-0898", "CVE-2013-0899", "CVE-2013-0900");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (dfd92cb2-7d48-11e2-ad48-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[172243] High CVE-2013-0879: Memory corruption with web audio node.
Credit to Atte Kettunen of OUSPG.

[171951] High CVE-2013-0880: Use-after-free in database handling.
Credit to Chamal de Silva.

[167069] Medium CVE-2013-0881: Bad read in Matroska handling. Credit
to Atte Kettunen of OUSPG.

[165432] High CVE-2013-0882: Bad memory access with excessive SVG
parameters. Credit to Renata Hodovan.

[142169] Medium CVE-2013-0883: Bad read in Skia. Credit to Atte
Kettunen of OUSPG.

[172984] Low CVE-2013-0884: Inappropriate load of NaCl. Credit to
Google Chrome Security Team (Chris Evans).

[172369] Medium CVE-2013-0885: Too many API permissions granted to web
store.

[171065] [170836] Low CVE-2013-0887: Developer tools process has too
many permissions and places too much trust in the connected server.

[170666] Medium CVE-2013-0888: Out-of-bounds read in Skia. Credit to
Google Chrome Security Team (Inferno).

[170569] Low CVE-2013-0889: Tighten user gesture check for dangerous
file downloads.

[169973] [169966] High CVE-2013-0890: Memory safety issues across the
IPC layer. Credit to Google Chrome Security Team (Chris Evans).

[169685] High CVE-2013-0891: Integer overflow in blob handling. Credit
to Google Chrome Security Team (Juri Aedla).

[169295] [168710] [166493] [165836] [165747] [164958] [164946] Medium
CVE-2013-0892: Lower severity issues across the IPC layer. Credit to
Google Chrome Security Team (Chris Evans).

[168570] Medium CVE-2013-0893: Race condition in media handling.
Credit to Andrew Scherkus of the Chromium development community.

[168473] High CVE-2013-0894: Buffer overflow in vorbis decoding.
Credit to Google Chrome Security Team (Inferno).

[Linux / Mac] [167840] High CVE-2013-0895: Incorrect path handling in
file copying. Credit to Google Chrome Security Team (Juri Aedla).

[166708] High CVE-2013-0896: Memory management issues in plug-in
message handling. Credit to Google Chrome Security Team (Cris Neckar).

[165537] Low CVE-2013-0897: Off-by-one read in PDF. Credit to Mateusz
Jurczyk, with contributions by Gynvael Coldwind, both from Google
Security Team.

[164643] High CVE-2013-0898: Use-after-free in URL handling. Credit to
Alexander Potapenko of the Chromium development community.

[160480] Low CVE-2013-0899: Integer overflow in Opus handling. Credit
to Google Chrome Security Team (Juri Aedla).

[152442] Medium CVE-2013-0900: Race condition in ICU. Credit to Google
Chrome Security Team (Inferno)."
  );
  # http://googlechromereleases.blogspot.nl/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdc75d6a"
  );
  # http://www.freebsd.org/ports/portaudit/dfd92cb2-7d48-11e2-ad48-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fad94d42"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/24");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<25.0.1364.97")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
