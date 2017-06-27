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
  script_id(91374);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:02:55 $");

  script_cve_id("CVE-2016-1660", "CVE-2016-1661", "CVE-2016-1662", "CVE-2016-1663", "CVE-2016-1664", "CVE-2016-1665", "CVE-2016-1666");

  script_name(english:"FreeBSD : chromium -- multiple vulnerablities (7da1da96-24bb-11e6-bd31-3065ec8fd3ec)");
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

9 security fixes in this release, including :

- [574802] High CVE-2016-1660: Out-of-bounds write in Blink. Credit to
Atte Kettunen of OUSPG.

- [601629] High CVE-2016-1661: Memory corruption in cross-process
frames. Credit to Wadih Matar.

- [603732] High CVE-2016-1662: Use-after-free in extensions. Credit to
Rob Wu.

- [603987] High CVE-2016-1663: Use-after-free in Blink's V8 bindings.
Credit to anonymous.

- [597322] Medium CVE-2016-1664: Address bar spoofing. Credit to Wadih
Matar.

- [606181] Medium CVE-2016-1665: Information leak in V8. Credit to
HyungSeok Han.

- [607652] CVE-2016-1666: Various fixes from internal audits, fuzzing
and other initiatives."
  );
  # http://googlechromereleases.blogspot.nl/2016/04/stable-channel-update_28.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22d8d53b"
  );
  # http://www.freebsd.org/ports/portaudit/7da1da96-24bb-11e6-bd31-3065ec8fd3ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa041acf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/31");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<50.0.2661.94")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<50.0.2661.94")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<50.0.2661.94")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
