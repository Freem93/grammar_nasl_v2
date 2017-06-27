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
  script_id(83095);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/05/24 04:37:33 $");

  script_cve_id("CVE-2015-1235", "CVE-2015-1236", "CVE-2015-1237", "CVE-2015-1238", "CVE-2015-1240", "CVE-2015-1241", "CVE-2015-1242", "CVE-2015-1244", "CVE-2015-1245", "CVE-2015-1246", "CVE-2015-1247", "CVE-2015-1248", "CVE-2015-1249");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (b57f690e-ecc9-11e4-876c-00262d5ed8ee)");
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

45 new security fixes, including :

- [456518] High CVE-2015-1235: Cross-origin-bypass in HTML parser.
Credit to anonymous.

- [313939] Medium CVE-2015-1236: Cross-origin-bypass in Blink. Credit
to Amitay Dobo.

- [461191] High CVE-2015-1237: Use-after-free in IPC. Credit to Khalil
Zhani.

- [445808] High CVE-2015-1238: Out-of-bounds write in Skia. Credit to
cloudfuzzer.

- [463599] Medium CVE-2015-1240: Out-of-bounds read in WebGL. Credit
to w3bd3vil.

- [418402] Medium CVE-2015-1241: Tap-Jacking. Credit to Phillip Moon
and Matt Weston of Sandfield Information Systems.

- [460917] High CVE-2015-1242: Type confusion in V8. Credit to
fcole@onshape.com.

- [455215] Medium CVE-2015-1244: HSTS bypass in WebSockets. Credit to
Mike Ruddy.

- [444957] Medium CVE-2015-1245: Use-after-free in PDFium. Credit to
Khalil Zhani.

- [437399] Medium CVE-2015-1246: Out-of-bounds read in Blink. Credit
to Atte Kettunen of OUSPG.

- [429838] Medium CVE-2015-1247: Scheme issues in OpenSearch. Credit
to Jann Horn.

- [380663] Medium CVE-2015-1248: SafeBrowsing bypass. Credit to
Vittorio Gambaletta (VittGam).

- [476786] CVE-2015-1249: Various fixes from internal audits, fuzzing
and other initiatives. Multiple vulnerabilities in V8 fixed at the tip
of the 4.2 branch (currently 4.2.77.14)."
  );
  # http://googlechromereleases.blogspot.nl/2015/04/stable-channel-update_14.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a57bf0f"
  );
  # http://www.freebsd.org/ports/portaudit/b57f690e-ecc9-11e4-876c-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d68a0ca4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<42.0.2311.90")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<42.0.2311.90")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<42.0.2311.90")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
