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
  script_id(89764);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/19 14:02:53 $");

  script_cve_id("CVE-2016-1624", "CVE-2016-1968");

  script_name(english:"FreeBSD : brotli -- buffer overflow (1bcfd963-e483-41b8-ab8e-bad5c3ce49c9)");
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

[583607] High CVE-2016-1624: Buffer overflow in Brotli. Credit to
lukezli.

Mozilla Foundation reports :

Security researcher Luke Li reported a pointer underflow bug in the
Brotli library's decompression that leads to a buffer overflow. This
results in a potentially exploitable crash when triggered."
  );
  # https://github.com/google/brotli/commit/37a320dd81db8d546cd24a45b4c61d87b45dcade
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9d76078"
  );
  # https://chromium.googlesource.com/chromium/src/+/7716418a27d561ee295a99f11fd3865580748de2%5E!/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?609f6b88"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-30/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://hg.mozilla.org/releases/mozilla-release/rev/4a5d8ade4e3e"
  );
  # http://www.freebsd.org/ports/portaudit/1bcfd963-e483-41b8-ab8e-bad5c3ce49c9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46877204"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:brotli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libbrotli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/09");
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

if (pkg_test(save_report:TRUE, pkg:"brotli>=0.3.0<0.3.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"brotli<0.2.0_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libbrotli<0.3.0_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium<48.0.2564.109")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<48.0.2564.109")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<48.0.2564.109")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox<45.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<45.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<38.7.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<38.7.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<38.7.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<38.7.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
