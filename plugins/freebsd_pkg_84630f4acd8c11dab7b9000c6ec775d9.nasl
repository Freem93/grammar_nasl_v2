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
  script_id(21461);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:42:11 $");

  script_cve_id("CVE-2006-0749", "CVE-2006-1045", "CVE-2006-1529", "CVE-2006-1530", "CVE-2006-1531", "CVE-2006-1723", "CVE-2006-1724", "CVE-2006-1725", "CVE-2006-1726", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
  script_xref(name:"CERT", value:"179014");
  script_xref(name:"CERT", value:"252324");
  script_xref(name:"CERT", value:"329500");
  script_xref(name:"CERT", value:"350262");
  script_xref(name:"CERT", value:"488774");
  script_xref(name:"CERT", value:"736934");
  script_xref(name:"CERT", value:"813230");
  script_xref(name:"CERT", value:"842094");
  script_xref(name:"CERT", value:"932734");
  script_xref(name:"CERT", value:"935556");
  script_xref(name:"CERT", value:"968814");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (84630f4a-cd8c-11da-b7b9-000c6ec775d9)");
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
"A Mozilla Foundation Security Advisory reports of multiple issues.
Several of which can be used to run arbitrary code with the privilege
of the user running the program.

- MFSA 2006-29 Spoofing with translucent windows

- MFSA 2006-28 Security check of js_ValueToFunctionObject() can be
circumvented

- MFSA 2006-26 Mail Multiple Information Disclosure

- MFSA 2006-25 Privilege escalation through Print Preview

- MFSA 2006-24 Privilege escalation using crypto.generateCRMFRequest

- MFSA 2006-23 File stealing by changing input type

- MFSA 2006-22 CSS Letter-Spacing Heap Overflow Vulnerability

- MFSA 2006-20 Crashes with evidence of memory corruption (rv:1.8.0.2)

- MFSA 2006-19 Cross-site scripting using .valueOf.call()

- MFSA 2006-18 Mozilla Firefox Tag Order Vulnerability

- MFSA 2006-17 cross-site scripting through window.controllers

- MFSA 2006-16 Accessing XBL compilation scope via valueOf.call()

- MFSA 2006-15 Privilege escalation using a JavaScript function's
cloned parent

- MFSA 2006-14 Privilege escalation via XBL.method.eval

- MFSA 2006-13 Downloading executables with 'Save Image As...'

- MFSA 2006-12 Secure-site spoof (requires security warning dialog)

- MFSA 2006-11 Crashes with evidence of memory corruption (rv:1.8)

- MFSA 2006-10 JavaScript garbage-collection hazard audit

- MFSA 2006-09 Cross-site JavaScript injection using event handlers"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-06-010.html"
  );
  # http://www.uscert.gov/cas/techalerts/TA06-107A.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6fa96c5c"
  );
  # http://www.freebsd.org/ports/portaudit/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?512256f0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<1.0.8,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox>1.5.*,1<1.5.0.2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<1.5.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla<1.7.13,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla>=1.8.*,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla<1.7.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla-devel>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<1.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<1.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<1.5.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-thunderbird<1.5.0.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
