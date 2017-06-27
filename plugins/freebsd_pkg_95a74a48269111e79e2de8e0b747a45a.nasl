#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2017 Jacques Vidrine and contributors
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
  script_id(99616);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/28 13:38:34 $");

  script_cve_id("CVE-2017-5057", "CVE-2017-5058", "CVE-2017-5059", "CVE-2017-5060", "CVE-2017-5061", "CVE-2017-5062", "CVE-2017-5063", "CVE-2017-5064", "CVE-2017-5065", "CVE-2017-5066", "CVE-2017-5067", "CVE-2017-5069");
  script_xref(name:"IAVB", value:"2017-B-0047");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (95a74a48-2691-11e7-9e2d-e8e0b747a45a)");
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

29 security fixes in this release, including :

- [695826] High CVE-2017-5057: Type confusion in PDFium. Credit to
Guang Gong of Alpha Team, Qihoo 360

- [694382] High CVE-2017-5058: Heap use after free in Print Preview.
Credit to Khalil Zhani

- [684684] High CVE-2017-5059: Type confusion in Blink. Credit to
SkyLined working with Trend Micro's Zero Day Initiative

- [683314] Medium CVE-2017-5060: URL spoofing in Omnibox. Credit to
Xudong Zheng

- [672847] Medium CVE-2017-5061: URL spoofing in Omnibox. Credit to
Haosheng Wang (@gnehsoah)

- [702896] Medium CVE-2017-5062: Use after free in Chrome Apps. Credit
to anonymous

- [700836] Medium CVE-2017-5063: Heap overflow in Skia. Credit to
Sweetchip

- [693974] Medium CVE-2017-5064: Use after free in Blink. Credit to
Wadih Matar

- [704560] Medium CVE-2017-5065: Incorrect UI in Blink. Credit to
Khalil Zhani

- [690821] Medium CVE-2017-5066: Incorrect signature handing in
Networking. Credit to Prof. Zhenhua Duan, Prof. Cong Tian, and Ph.D
candidate Chu Chen (ICTT, Xidian University)

- [648117] Medium CVE-2017-5067: URL spoofing in Omnibox. Credit to
Khalil Zhani

- [691726] Low CVE-2017-5069: Cross-origin bypass in Blink. Credit to
Michael Reizelman

- [713205] Various fixes from internal audits, fuzzing and other
initiatives"
  );
  # https://chromereleases.googleblog.com/2017/04/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9ef6b47"
  );
  # http://www.freebsd.org/ports/portaudit/95a74a48-2691-11e7-9e2d-e8e0b747a45a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02a77246"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<58.0.3029.81")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<58.0.3029.81")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
