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
  script_id(89765);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/19 14:02:53 $");

  script_cve_id("CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954", "CVE-2016-1955", "CVE-2016-1956", "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1959", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1963", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1967", "CVE-2016-1970", "CVE-2016-1971", "CVE-2016-1972", "CVE-2016-1973", "CVE-2016-1974", "CVE-2016-1975", "CVE-2016-1976");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (2225c5b4-1e5a-44fc-9920-b3201c384a15)");
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
"Mozilla Foundation reports :

MFSA 2016-16 Miscellaneous memory safety hazards (rv:45.0 / rv:38.7)

MFSA 2016-17 Local file overwriting and potential privilege escalation
through CSP reports

MFSA 2016-18 CSP reports fail to strip location information for
embedded iframe pages

MFSA 2016-19 Linux video memory DOS with Intel drivers

MFSA 2016-20 Memory leak in libstagefright when deleting an array
during MP4 processing

MFSA 2016-21 Displayed page address can be overridden

MFSA 2016-22 Service Worker Manager out-of-bounds read in Service
Worker Manager

MFSA 2016-23 Use-after-free in HTML5 string parser

MFSA 2016-24 Use-after-free in SetBody

MFSA 2016-25 Use-after-free when using multiple WebRTC data channels

MFSA 2016-26 Memory corruption when modifying a file being read by
FileReader

MFSA 2016-27 Use-after-free during XML transformations

MFSA 2016-28 Addressbar spoofing though history navigation and
Location protocol property

MFSA 2016-29 Same-origin policy violation using perfomance.getEntries
and history navigation with session restore

MFSA 2016-31 Memory corruption with malicious NPAPI plugin

MFSA 2016-32 WebRTC and LibVPX vulnerabilities found through code
inspection

MFSA 2016-33 Use-after-free in GetStaticInstance in WebRTC

MFSA 2016-34 Out-of-bounds read in HTML parser following a failed
allocation"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-16/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-17/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-18/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-19/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-20/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-21/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-22/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-23/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-24/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-25/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-26/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-27/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-28/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-29/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-31/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-32/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-33/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-34/"
  );
  # http://www.freebsd.org/ports/portaudit/2225c5b4-1e5a-44fc-9920-b3201c384a15.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?346e5004"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
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
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
