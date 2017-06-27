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
  script_id(66549);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/21 23:48:19 $");

  script_cve_id("CVE-2013-2836", "CVE-2013-2837", "CVE-2013-2838", "CVE-2013-2839", "CVE-2013-2840", "CVE-2013-2841", "CVE-2013-2842", "CVE-2013-2843", "CVE-2013-2844", "CVE-2013-2845", "CVE-2013-2846", "CVE-2013-2847", "CVE-2013-2848", "CVE-2013-2849");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (358133b5-c2b9-11e2-a738-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[235638] High CVE-2013-2837: Use-after-free in SVG. Credit to Slawomir
Blazek.

[235311] Medium CVE-2013-2838: Out-of-bounds read in v8. Credit to
Christian Holler.

[230176] High CVE-2013-2839: Bad cast in clipboard handling. Credit to
Jon of MWR InfoSecurity.

[230117] High CVE-2013-2840: Use-after-free in media loader. Credit to
Nils of MWR InfoSecurity.

[227350] High CVE-2013-2841: Use-after-free in Pepper resource
handling. Credit to Chamal de Silva.

[226696] High CVE-2013-2842: Use-after-free in widget handling. Credit
to Cyril Cattiaux.

[222000] High CVE-2013-2843: Use-after-free in speech handling. Credit
to Khalil Zhani.

[196393] High CVE-2013-2844: Use-after-free in style resolution.
Credit to Sachin Shinde (@cons0ul).

[188092] [179522] [222136] [188092] High CVE-2013-2845: Memory safety
issues in Web Audio. Credit to Atte Kettunen of OUSPG.

[177620] High CVE-2013-2846: Use-after-free in media loader. Credit to
Chamal de Silva.

[176692] High CVE-2013-2847: Use-after-free race condition with
workers. Credit to Collin Payne.

[176137] Medium CVE-2013-2848: Possible data extraction with XSS
Auditor. Credit to Egor Homakov.

[171392] Low CVE-2013-2849: Possible XSS with drag+drop or copy+paste.
Credit to Mario Heiderich.

[241595] High CVE-2013-2836: Various fixes from internal audits,
fuzzing and other initiatives."
  );
  # http://googlechromereleases.blogspot.nl/search/Stable%20Updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bd43a3e"
  );
  # http://www.freebsd.org/ports/portaudit/358133b5-c2b9-11e2-a738-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?151e7dec"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/23");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<27.0.1453.93")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
