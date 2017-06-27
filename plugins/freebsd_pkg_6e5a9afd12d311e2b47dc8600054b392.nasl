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
  script_id(62490);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/12 13:22:47 $");

  script_cve_id("CVE-2012-3982", "CVE-2012-3983", "CVE-2012-3984", "CVE-2012-3985", "CVE-2012-3986", "CVE-2012-3987", "CVE-2012-3988", "CVE-2012-3989", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188", "CVE-2012-4190", "CVE-2012-4191", "CVE-2012-4192", "CVE-2012-4193");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (6e5a9afd-12d3-11e2-b47d-c8600054b392)");
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
"The Mozilla Project reports :

MFSA 2012-74 Miscellaneous memory safety hazards (rv:16.0/ rv:10.0.8)

MFSA 2012-75 select element persistance allows for attacks

MFSA 2012-76 Continued access to initial origin after setting
document.domain

MFSA 2012-77 Some DOMWindowUtils methods bypass security checks

MFSA 2012-78 Reader Mode pages have chrome privileges

MFSA 2012-79 DOS and crash with full screen and history navigation

MFSA 2012-80 Crash with invalid cast when using instanceof operator

MFSA 2012-81 GetProperty function can bypass security checks

MFSA 2012-82 top object and location property accessible by plugins

MFSA 2012-83 Chrome Object Wrapper (COW) does not disallow access to
privileged functions or properties

MFSA 2012-84 Spoofing and script injection through location.hash

MFSA 2012-85 Use-after-free, buffer overflow, and out of bounds read
issues found using Address Sanitizer

MFSA 2012-86 Heap memory corruption issues found using Address
Sanitizer

MFSA 2012-87 Use-after-free in the IME State Manager

MFSA 2012-88 Miscellaneous memory safety hazards (rv:16.0.1)

MFSA 2012-89 defaultValue security checks not applied"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-vulnerabilities/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-74.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-75.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-76.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-77.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-78.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-79.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-80.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-81.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-82.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-83.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-84.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-85.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-86.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-87.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-88.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-89.html"
  );
  # http://www.freebsd.org/ports/portaudit/6e5a9afd-12d3-11e2-b47d-c8600054b392.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?900d0765"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox>11.0,1<16.0.1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox<10.0.9,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<10.0.9,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.13.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<10.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.13.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird>11.0<16.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<10.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul>1.9.2.*<10.0.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
