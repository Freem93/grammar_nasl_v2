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
  script_id(94904);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/05 16:04:17 $");

  script_cve_id("CVE-2016-5289", "CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5292", "CVE-2016-5293", "CVE-2016-5294", "CVE-2016-5295", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-5298", "CVE-2016-5299", "CVE-2016-9061", "CVE-2016-9062", "CVE-2016-9063", "CVE-2016-9064", "CVE-2016-9065", "CVE-2016-9066", "CVE-2016-9067", "CVE-2016-9068", "CVE-2016-9070", "CVE-2016-9071", "CVE-2016-9072", "CVE-2016-9073", "CVE-2016-9074", "CVE-2016-9075", "CVE-2016-9076", "CVE-2016-9077");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (d1853110-07f4-4645-895b-6fd462ad0589)");
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

CVE-2016-5289: Memory safety bugs fixed in Firefox 50

CVE-2016-5290: Memory safety bugs fixed in Firefox 50 and Firefox ESR
45.5

CVE-2016-5291: Same-origin policy violation using local HTML file and
saved shortcut file

CVE-2016-5292: URL parsing causes crash

CVE-2016-5293: Write to arbitrary file with updater and moz
maintenance service using updater.log h

CVE-2016-5294: Arbitrary target directory for result files of update
process

CVE-2016-5295: Mozilla Maintenance Service: Ability to read arbitrary
files as SYSTEM

CVE-2016-5296: Heap-buffer-overflow WRITE in rasterize_edges_1

CVE-2016-5297: Incorrect argument length checking in JavaScript

CVE-2016-5298: SSL indicator can mislead the user about the real URL
visited

CVE-2016-5299: Firefox AuthToken in broadcast protected with
signature-level permission can be accessed by an app

CVE-2016-9061: API Key (glocation) in broadcast protected with
signature-level permission can be accessed by an a

CVE-2016-9062: Private browsing browser traces (android) in browser.db
and wal file

CVE-2016-9063: Possible integer overflow to fix inside XML_Parse in
expat

CVE-2016-9064: Addons update must verify IDs match between current and
new versions

CVE-2016-9065: Firefox for Android location bar spoofing using
fullscreen

CVE-2016-9066: Integer overflow leading to a buffer overflow in
nsScriptLoadHandler

CVE-2016-9067: heap-use-after-free in nsINode::ReplaceOrInsertBefore

CVE-2016-9068: heap-use-after-free in nsRefreshDriver

CVE-2016-9070: Sidebar bookmark can have reference to chrome window

CVE-2016-9071: Probe browser history via HSTS/301 redirect + CSP

CVE-2016-9072: 64-bit NPAPI sandbox isn't enabled on fresh profile

CVE-2016-9073: windows.create schema doesn't specify 'format':
'relativeUrl'

CVE-2016-9074: Insufficient timing side-channel resistance in
divSpoiler

CVE-2016-9075: WebExtensions can access the mozAddonManager API and
use it to gain elevated privileges

CVE-2016-9076: select dropdown menu can be used for URL bar spoofing
on e10s

CVE-2016-9077: Canvas filters allow feDisplacementMaps to be applied
to cross-origin images, allowing timing atta"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-89/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-90/"
  );
  # http://www.freebsd.org/ports/portaudit/d1853110-07f4-4645-895b-6fd462ad0589.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9915ed26"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/16");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<50.0_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.47")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.47")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<45.5.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<45.5.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<45.5.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<45.5.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<45.5.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
