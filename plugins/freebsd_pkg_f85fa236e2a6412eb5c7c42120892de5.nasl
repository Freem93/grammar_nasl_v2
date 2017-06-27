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
  script_id(89711);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/19 14:14:42 $");

  script_cve_id("CVE-2016-1630", "CVE-2016-1631", "CVE-2016-1632", "CVE-2016-1633", "CVE-2016-1634", "CVE-2016-1635", "CVE-2016-1636", "CVE-2016-1637", "CVE-2016-1638", "CVE-2016-1639", "CVE-2016-1640", "CVE-2016-1641", "CVE-2016-1642");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (f85fa236-e2a6-412e-b5c7-c42120892de5)");
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

[560011] High CVE-2016-1630: Same-origin bypass in Blink.

[569496] High CVE-2016-1631: Same-origin bypass in Pepper Plugin.

[549986] High CVE-2016-1632: Bad cast in Extensions.

[572537] High CVE-2016-1633: Use-after-free in Blink.

[559292] High CVE-2016-1634: Use-after-free in Blink.

[585268] High CVE-2016-1635: Use-after-free in Blink.

[584155] High CVE-2016-1636: SRI Validation Bypass.

[555544] Medium CVE-2016-1637: Information Leak in Skia.

[585282] Medium CVE-2016-1638: WebAPI Bypass.

[572224] Medium CVE-2016-1639: Use-after-free in WebRTC.

[550047] Medium CVE-2016-1640: Origin confusion in Extensions UI.

[583718] Medium CVE-2016-1641: Use-after-free in Favicon.

[591402] CVE-2016-1642: Various fixes from internal audits, fuzzing
and other initiatives.

Multiple vulnerabilities in V8 fixed."
  );
  # http://googlechromereleases.blogspot.de/2016/03/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d178279b"
  );
  # http://www.freebsd.org/ports/portaudit/f85fa236-e2a6-412e-b5c7-c42120892de5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07bdc6d7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/07");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<49.0.2623.75")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<49.0.2623.75")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<49.0.2623.75")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
