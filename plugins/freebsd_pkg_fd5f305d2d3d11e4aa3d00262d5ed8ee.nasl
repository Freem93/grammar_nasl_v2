#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(77401);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/12 15:28:26 $");

  script_cve_id("CVE-2014-3168", "CVE-2014-3169", "CVE-2014-3170", "CVE-2014-3171", "CVE-2014-3172", "CVE-2014-3173", "CVE-2014-3174", "CVE-2014-3175", "CVE-2014-3176", "CVE-2014-3177");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (fd5f305d-2d3d-11e4-aa3d-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

50 security fixes in this release, including :

- [386988] Critical CVE-2014-3176, CVE-2014-3177: A special reward to
lokihardt@asrt for a combination of bugs in V8, IPC, sync, and
extensions that can lead to remote code execution outside of the
sandbox.

- [369860] High CVE-2014-3168: Use-after-free in SVG. Credit to
cloudfuzzer.

- [387389] High CVE-2014-3169: Use-after-free in DOM. Credit to
Andrzej Dyjak.

- [390624] High CVE-2014-3170: Extension permission dialog spoofing.
Credit to Rob Wu.

- [390928] High CVE-2014-3171: Use-after-free in bindings. Credit to
cloudfuzzer.

- [367567] Medium CVE-2014-3172: Issue related to extension debugging.
Credit to Eli Grey.

- [376951] Medium CVE-2014-3173: Uninitialized memory read in WebGL.
Credit to jmuizelaar.

- [389219] Medium CVE-2014-3174: Uninitialized memory read in Web
Audio. Credit to Atte Kettunen from OUSPG.

- [406143] CVE-2014-3175: Various fixes from internal audits, fuzzing
and other initiatives (Chrome 37)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://googlechromereleases.blogspot.nl/"
  );
  # http://www.freebsd.org/ports/portaudit/fd5f305d-2d3d-11e4-aa3d-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfd714dc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<37.0.2062.94")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
