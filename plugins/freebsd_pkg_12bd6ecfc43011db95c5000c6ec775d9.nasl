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
  script_id(24705);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/08 20:31:55 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0995", "CVE-2007-1092");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (12bd6ecf-c430-11db-95c5-000c6ec775d9)");
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
"The Mozilla Foundation reports of multiple security issues in Firefox,
SeaMonkey, and Thunderbird. Several of these issues can probably be
used to run arbitrary code with the privilege of the user running the
program.

- MFSA 2007-08 onUnload + document.write() memory corruption

- MFSA 2007-07 Embedded nulls in location.hostname confuse same-domain
checks

- MFSA 2007-06 Mozilla Network Security Services (NSS) SSLv2 buffer
overflow

- MFSA 2007-05 XSS and local file access by opening blocked popups

- MFSA 2007-04 Spoofing using custom cursor and CSS3 hotspot

- MFSA 2007-03 Information disclosure through cache collisions

- MFSA 2007-02 Improvements to help protect against Cross-Site
Scripting attacks

- MFSA 2007-01 Crashes with evidence of memory corruption
(rv:1.8.0.10/1.8.1.2)"
  );
  # http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=482
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33a699df"
  );
  # http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=483
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca72b322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-04.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-06.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-07.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-08.html"
  );
  # http://www.freebsd.org/ports/portaudit/12bd6ecf-c430-11db-95c5-000c6ec775d9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d91bf6e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:lightning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<1.5.0.10,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox>2.*,1<2.0.0.2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<1.5.0.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"lightning<0.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<1.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey>=1.1<1.1.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<1.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey>=1.1<1.1.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<1.5.0.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<1.5.0.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-thunderbird<1.5.0.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox-devel<3.0.a2007.04.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey-devel<1.5.a2007.04.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-ja>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla-devel>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla>0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
