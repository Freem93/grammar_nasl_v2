#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(73779);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/14 00:01:14 $");

  script_cve_id("CVE-2014-1492", "CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1520", "CVE-2014-1522", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526", "CVE-2014-1527", "CVE-2014-1528", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (985d4d6c-cfbd-11e3-a003-b4b52fce4ce8)");
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

MFSA 2014-34 Miscellaneous memory safety hazards (rv:29.0 / rv:24.5)

MFSA 2014-35 Privilege escalation through Mozilla Maintenance Service
Installer

MFSA 2014-36 Web Audio memory corruption issues

MFSA 2014-37 Out of bounds read while decoding JPG images

MFSA 2014-38 Buffer overflow when using non-XBL object as XBL

MFSA 2014-39 Use-after-free in the Text Track Manager for HTML video

MFSA 2014-41 Out-of-bounds write in Cairo

MFSA 2014-42 Privilege escalation through Web Notification API

MFSA 2014-43 Cross-site scripting (XSS) using history navigations

MFSA 2014-44 Use-after-free in imgLoader while resizing images

MFSA 2014-45 Incorrect IDNA domain name matching for wildcard
certificates

MFSA 2014-46 Use-after-free in nsHostResolve

MFSA 2014-47 Debugger can bypass XrayWrappers with JavaScript"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-35.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-41.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-43.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-46.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-47.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-vulnerabilities/"
  );
  # http://www.freebsd.org/ports/portaudit/985d4d6c-cfbd-11e3-a003-b4b52fce4ce8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?768ced83"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<29.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<24.5.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<29.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<24.5.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<24.5.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
