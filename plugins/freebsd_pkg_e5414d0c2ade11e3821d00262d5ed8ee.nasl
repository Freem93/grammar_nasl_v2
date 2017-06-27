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
  script_id(70265);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2013-2906", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909", "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913", "CVE-2013-2914", "CVE-2013-2915", "CVE-2013-2916", "CVE-2013-2917", "CVE-2013-2918", "CVE-2013-2919", "CVE-2013-2920", "CVE-2013-2921", "CVE-2013-2922", "CVE-2013-2923", "CVE-2013-2924");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (e5414d0c-2ade-11e3-821d-00262d5ed8ee)");
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

- [223962][270758][271161][284785][284786] Medium CVE-2013-2906 :
Races in Web Audio. Credit to Atte Kettunen of OUSPG.

- [260667] Medium CVE-2013-2907: Out of bounds read in
Window.prototype object. Credit to Boris Zbarsky.

- [265221] Medium CVE-2013-2908: Address bar spoofing related to the
'204 No Content' status code. Credit to Chamal de Silva.

- [265838][279277] High CVE-2013-2909: Use after free in inline-block
rendering. Credit to Atte Kettunen of OUSPG.

- [269753] Medium CVE-2013-2910: Use-after-free in Web Audio. Credit
to Byoungyoung Lee of Georgia Tech Information Security Center
(GTISC).

- [271939] High CVE-2013-2911: Use-after-free in XSLT. Credit to Atte
Kettunen of OUSPG.

- [276368] High CVE-2013-2912: Use-after-free in PPAPI. Credit to
Chamal de Silva and 41.w4r10r(at)garage4hackers.com.

- [278908] High CVE-2013-2913: Use-after-free in XML document parsing.
Credit to cloudfuzzer.

- [279263] High CVE-2013-2914: Use after free in the Windows color
chooser dialog. Credit to Khalil Zhani.

- [280512] Low CVE-2013-2915: Address bar spoofing via a malformed
scheme. Credit to Wander Groeneveld. 

- [281256] High CVE-2013-2916: Address bar spoofing related to the
'204 No Content' status code. Credit to Masato Kinugawa.

- [281480] Medium CVE-2013-2917: Out of bounds read in Web Audio.
Credit to Byoungyoung Lee and Tielei Wang of Georgia Tech Information
Security Center (GTISC).

- [282088] High CVE-2013-2918: Use-after-free in DOM. Credit to
Byoungyoung Lee of Georgia Tech Information Security Center (GTISC).

- [282736] High CVE-2013-2919: Memory corruption in V8. Credit to Adam
Haile of Concrete Data.

- [285742] Medium CVE-2013-2920: Out of bounds read in URL parsing.
Credit to Atte Kettunen of OUSPG.

- [286414] High CVE-2013-2921: Use-after-free in resource loader.
Credit to Byoungyoung Lee and Tielei Wang of Georgia Tech Information
Security Center (GTISC).

- [286975] High CVE-2013-2922: Use-after-free in template element.
Credit to Jon Butler.

- [299016] CVE-2013-2923: Various fixes from internal audits, fuzzing
and other initiatives (Chrome 30).

- [275803] Medium CVE-2013-2924: Use-after-free in ICU. Upstream bug
here."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://googlechromereleases.blogspot.nl/"
  );
  # http://www.freebsd.org/ports/portaudit/e5414d0c-2ade-11e3-821d-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ace320ee"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/02");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<30.0.1599.66")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
