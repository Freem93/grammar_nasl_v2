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
  script_id(65850);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/12/05 14:06:23 $");

  script_cve_id("CVE-2013-0916", "CVE-2013-0917", "CVE-2013-0918", "CVE-2013-0919", "CVE-2013-0920", "CVE-2013-0921", "CVE-2013-0922", "CVE-2013-0923", "CVE-2013-0924", "CVE-2013-0925", "CVE-2013-0926");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (bdd48858-9656-11e2-a9a8-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[172342] High CVE-2013-0916: Use-after-free in Web Audio. Credit to
Atte Kettunen of OUSPG.

[180909] Low CVE-2013-0917: Out-of-bounds read in URL loader. Credit
to Google Chrome Security Team (Cris Neckar).

[180555] Low CVE-2013-0918: Do not navigate dev tools upon drag and
drop. Credit to Vsevolod Vlasov of the Chromium development community.

[Linux only] [178760] Medium CVE-2013-0919: Use-after-free with pop-up
windows in extensions. Credit to Google Chrome Security Team (Mustafa
Emre Acer).

[177410] Medium CVE-2013-0920: Use-after-free in extension bookmarks
API. Credit to Google Chrome Security Team (Mustafa Emre Acer).

[174943] High CVE-2013-0921: Ensure isolated web sites run in their
own processes.

[174129] Low CVE-2013-0922: Avoid HTTP basic auth brute-force
attempts. Credit to 't3553r'.

[169981] [169972] [169765] Medium CVE-2013-0923: Memory safety issues
in the USB Apps API. Credit to Google Chrome Security Team (Mustafa
Emre Acer).

[169632] Low CVE-2013-0924: Check an extension's permissions API usage
again file permissions. Credit to Benjamin Kalman of the Chromium
development community.

[168442] Low CVE-2013-0925: Avoid leaking URLs to extensions without
the tabs permissions. Credit to Michael Vrable of Google.

[112325] Medium CVE-2013-0926: Avoid pasting active tags in certain
situations. Credit to Subho Halder, Aditya Gupta, and Dev Kar of xys3c
(xysec.com)."
  );
  # http://googlechromereleases.blogspot.nl/search/Stable%20Updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bd43a3e"
  );
  # http://www.freebsd.org/ports/portaudit/bdd48858-9656-11e2-a9a8-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a5ef16f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/08");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<26.0.1410.43")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
