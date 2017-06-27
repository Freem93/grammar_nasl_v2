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
  script_id(92537);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/19 14:02:54 $");

  script_cve_id("CVE-2016-1705", "CVE-2016-1706", "CVE-2016-1708", "CVE-2016-1709", "CVE-2016-1710", "CVE-2016-1711", "CVE-2016-5127", "CVE-2016-5128", "CVE-2016-5129", "CVE-2016-5130", "CVE-2016-5131", "CVE-2016-5132", "CVE-2016-5133", "CVE-2016-5134", "CVE-2016-5135", "CVE-2016-5136", "CVE-2016-5137");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (6fae9fe1-5048-11e6-8aa7-3065ec8fd3ec)");
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

48 security fixes in this release, including :

- [610600] High CVE-2016-1706: Sandbox escape in PPAPI. Credit to
Pinkie Pie xisigr of Tencent's Xuanwu Lab

- [613949] High CVE-2016-1708: Use-after-free in Extensions. Credit to
Adam Varsan

- [614934] High CVE-2016-1709: Heap-buffer-overflow in sfntly. Credit
to ChenQin of Topsec Security Team

- [616907] High CVE-2016-1710: Same-origin bypass in Blink. Credit to
Mariusz Mlynski

- [617495] High CVE-2016-1711: Same-origin bypass in Blink. Credit to
Mariusz Mlynski

- [618237] High CVE-2016-5127: Use-after-free in Blink. Credit to
cloudfuzzer

- [619166] High CVE-2016-5128: Same-origin bypass in V8. Credit to
Anonymous

- [620553] High CVE-2016-5129: Memory corruption in V8. Credit to
Jeonghoon Shin

- [623319] High CVE-2016-5130: URL spoofing. Credit to Wadih Matar

- [623378] High CVE-2016-5131: Use-after-free in libxml. Credit to
Nick Wellnhofer

- [607543] Medium CVE-2016-5132: Limited same-origin bypass in Service
Workers. Credit to Ben Kelly

- [613626] Medium CVE-2016-5133: Origin confusion in proxy
authentication. Credit to Patch Eudor

- [593759] Medium CVE-2016-5134: URL leakage via PAC script. Credit to
Paul Stone

- [605451] Medium CVE-2016-5135: Content-Security-Policy bypass.
Credit to kingxwy

- [625393] Medium CVE-2016-5136: Use after free in extensions. Credit
to Rob Wu

- [625945] Medium CVE-2016-5137: History sniffing with HSTS and CSP.
Credit to Xiaoyin Liu

- [629852] CVE-2016-1705: Various fixes from internal audits, fuzzing
and other initiatives."
  );
  # https://googlechromereleases.blogspot.nl/2016/07/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f4bd83a"
  );
  # http://www.freebsd.org/ports/portaudit/6fae9fe1-5048-11e6-8aa7-3065ec8fd3ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6d339fd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<52.0.2743.82")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<52.0.2743.82")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<52.0.2743.82")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
