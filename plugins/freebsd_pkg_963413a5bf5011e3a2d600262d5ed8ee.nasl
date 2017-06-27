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
  script_id(73431);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/12 14:02:26 $");

  script_cve_id("CVE-2014-1716", "CVE-2014-1717", "CVE-2014-1718", "CVE-2014-1719", "CVE-2014-1720", "CVE-2014-1721", "CVE-2014-1722", "CVE-2014-1723", "CVE-2014-1724", "CVE-2014-1725", "CVE-2014-1726", "CVE-2014-1727", "CVE-2014-1728", "CVE-2014-1729");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (963413a5-bf50-11e3-a2d6-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

31 vulnerabilities fixed in this release, including :

- [354123] High CVE-2014-1716: UXSS in V8. Credit to Anonymous.

- [353004] High CVE-2014-1717: OOB access in V8. Credit to Anonymous.

- [348332] High CVE-2014-1718: Integer overflow in compositor. Credit
to Aaron Staple.

- [343661] High CVE-2014-1719: Use-after-free in web workers. Credit
to Collin Payne.

- [356095] High CVE-2014-1720: Use-after-free in DOM. Credit to
cloudfuzzer.

- [350434] High CVE-2014-1721: Memory corruption in V8. Credit to
Christian Holler.

- [330626] High CVE-2014-1722: Use-after-free in rendering. Credit to
miaubiz.

- [337746] High CVE-2014-1723: Url confusion with RTL characters.
Credit to George McBay.

- [327295] High CVE-2014-1724: Use-after-free in speech. Credit to
Atte Kettunen of OUSPG.

- [357332] Medium CVE-2014-1725: OOB read with window property. Credit
to Anonymous

- [346135] Medium CVE-2014-1726: Local cross-origin bypass. Credit to
Jann Horn.

- [342735] Medium CVE-2014-1727: Use-after-free in forms. Credit to
Khalil Zhani.

- [360298] CVE-2014-1728: Various fixes from internal audits, fuzzing
and other initiatives.

- [345820, 347262, 348319, 350863, 352982, 355586, 358059]
CVE-2014-1729: Multiple vulnerabilities in V8 fixed in version
3.24.35.22."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://googlechromereleases.blogspot.nl/"
  );
  # http://www.freebsd.org/ports/portaudit/963413a5-bf50-11e3-a2d6-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb0a025b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<34.0.1847.116")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
