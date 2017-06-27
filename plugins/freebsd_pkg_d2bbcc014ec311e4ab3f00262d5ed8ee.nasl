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

include("compat.inc");

if (description)
{
  script_id(78104);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/26 16:04:31 $");

  script_cve_id("CVE-2014-3188", "CVE-2014-3189", "CVE-2014-3190", "CVE-2014-3191", "CVE-2014-3192", "CVE-2014-3193", "CVE-2014-3194", "CVE-2014-3195", "CVE-2014-3196", "CVE-2014-3197", "CVE-2014-3198", "CVE-2014-3199", "CVE-2014-3200");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (d2bbcc01-4ec3-11e4-ab3f-00262d5ed8ee)");
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

159 security fixes in this release, including 113 found using
MemorySanitizer :

- [416449] Critical CVE-2014-3188: A special thanks to Juri Aedla for
a combination of V8 and IPC bugs that can lead to remote code
execution outside of the sandbox.

- [398384] High CVE-2014-3189: Out-of-bounds read in PDFium. Credit to
cloudfuzzer.

- [400476] High CVE-2014-3190: Use-after-free in Events. Credit to
cloudfuzzer.

- [402407] High CVE-2014-3191: Use-after-free in Rendering. Credit to
cloudfuzzer.

- [403276] High CVE-2014-3192: Use-after-free in DOM. Credit to
cloudfuzzer.

- [399655] High CVE-2014-3193: Type confusion in Session Management.
Credit to miaubiz.

- [401115] High CVE-2014-3194: Use-after-free in Web Workers. Credit
to Collin Payne.

- [403409] Medium CVE-2014-3195: Information Leak in V8. Credit to
Juri Aedla.

- [338538] Medium CVE-2014-3196: Permissions bypass in Windows
Sandbox. Credit to James Forshaw.

- [396544] Medium CVE-2014-3197: Information Leak in XSS Auditor.
Credit to Takeshi Terada.

- [415307] Medium CVE-2014-3198: Out-of-bounds read in PDFium. Credit
to Atte Kettunen of OUSPG.

- [395411] Low CVE-2014-3199: Release Assert in V8 bindings. Credit to
Collin Payne.

- [420899] CVE-2014-3200: Various fixes from internal audits, fuzzing
and other initiatives (Chrome 38).

- Multiple vulnerabilities in V8 fixed at the tip of the 3.28 branch
(currently 3.28.71.15)."
  );
  # http://googlechromereleases.blogspot.nl/2014/10/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fab8e882"
  );
  # http://www.freebsd.org/ports/portaudit/d2bbcc01-4ec3-11e4-ab3f-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25293c88"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<38.0.2125.101")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<38.0.2125.101")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
