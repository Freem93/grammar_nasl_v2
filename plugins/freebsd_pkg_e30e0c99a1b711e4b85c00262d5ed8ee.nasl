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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80898);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/11 15:46:02 $");

  script_cve_id("CVE-2014-7923", "CVE-2014-7924", "CVE-2014-7925", "CVE-2014-7926", "CVE-2014-7927", "CVE-2014-7928", "CVE-2014-7929", "CVE-2014-7930", "CVE-2014-7931", "CVE-2014-7932", "CVE-2014-7933", "CVE-2014-7934", "CVE-2014-7935", "CVE-2014-7936", "CVE-2014-7937", "CVE-2014-7938", "CVE-2014-7939", "CVE-2014-7940", "CVE-2014-7941", "CVE-2014-7942", "CVE-2014-7943", "CVE-2014-7944", "CVE-2014-7945", "CVE-2014-7946", "CVE-2014-7947", "CVE-2014-7948", "CVE-2015-1205");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (e30e0c99-a1b7-11e4-b85c-00262d5ed8ee)");
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

62 security fixes in this release, including :

- [430353] High CVE-2014-7923: Memory corruption in ICU. Credit to
yangdingning.

- [435880] High CVE-2014-7924: Use-after-free in IndexedDB. Credit to
Collin Payne.

- [434136] High CVE-2014-7925: Use-after-free in WebAudio. Credit to
mark.buer.

- [422824] High CVE-2014-7926: Memory corruption in ICU. Credit to
yangdingning.

- [444695] High CVE-2014-7927: Memory corruption in V8. Credit to
Christian Holler.

- [435073] High CVE-2014-7928: Memory corruption in V8. Credit to
Christian Holler.

- [442806] High CVE-2014-7930: Use-after-free in DOM. Credit to
cloudfuzzer.

- [442710] High CVE-2014-7931: Memory corruption in V8. Credit to
cloudfuzzer.

- [443115] High CVE-2014-7929: Use-after-free in DOM. Credit to
cloudfuzzer.

- [429666] High CVE-2014-7932: Use-after-free in DOM. Credit to Atte
Kettunen of OUSPG.

- [427266] High CVE-2014-7933: Use-after-free in FFmpeg. Credit to
aohelin.

- [427249] High CVE-2014-7934: Use-after-free in DOM. Credit to
cloudfuzzer.

- [402957] High CVE-2014-7935: Use-after-free in Speech. Credit to
Khalil Zhani.

- [428561] High CVE-2014-7936: Use-after-free in Views. Credit to
Christoph Diehl.

- [419060] High CVE-2014-7937: Use-after-free in FFmpeg. Credit to
Atte Kettunen of OUSPG.

- [416323] High CVE-2014-7938: Memory corruption in Fonts. Credit to
Atte Kettunen of OUSPG.

- [399951] High CVE-2014-7939: Same-origin-bypass in V8. Credit to
Takeshi Terada.

- [433866] Medium CVE-2014-7940: Uninitialized-value in ICU. Credit to
miaubiz.

- [428557] Medium CVE-2014-7941: Out-of-bounds read in UI. Credit to
Atte Kettunen of OUSPG and Christoph Diehl.

- [426762] Medium CVE-2014-7942: Uninitialized-value in Fonts. Credit
to miaubiz.

- [422492] Medium CVE-2014-7943: Out-of-bounds read in Skia. Credit to
Atte Kettunen of OUSPG.

- [418881] Medium CVE-2014-7944: Out-of-bounds read in PDFium. Credit
to cloudfuzzer.

- [414310] Medium CVE-2014-7945: Out-of-bounds read in PDFium. Credit
to cloudfuzzer.

- [414109] Medium CVE-2014-7946: Out-of-bounds read in Fonts. Credit
to miaubiz.

- [430566] Medium CVE-2014-7947: Out-of-bounds read in PDFium. Credit
to fuzztercluck.

- [414026] Medium CVE-2014-7948: Caching error in AppCache. Credit to
jiayaoqijia.

- [449894] CVE-2015-1205: Various fixes from internal audits, fuzzing
and other initiatives.

- Multiple vulnerabilities in V8 fixed at the tip of the 3.30 branch
(currently 3.30.33.15)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://googlechromereleases.blogspot.nl"
  );
  # http://www.freebsd.org/ports/portaudit/e30e0c99-a1b7-11e4-b85c-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99e1a51c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<40.0.2214.91")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<40.0.2214.91")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
