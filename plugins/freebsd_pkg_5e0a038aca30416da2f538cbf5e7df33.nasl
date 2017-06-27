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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(99496);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5437", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5450", "CVE-2017-5451", "CVE-2017-5452", "CVE-2017-5453", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456", "CVE-2017-5458", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5463", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5468", "CVE-2017-5469");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (5e0a038a-ca30-416d-a2f5-38cbf5e7df33)");
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

CVE-2017-5433: Use-after-free in SMIL animation functions

CVE-2017-5435: Use-after-free during transaction processing in the
editor

CVE-2017-5436: Out-of-bounds write with malicious font in Graphite 2

CVE-2017-5461: Out-of-bounds write in Base64 encoding in NSS

CVE-2017-5459: Buffer overflow in WebGL

CVE-2017-5466: Origin confusion when reloading isolated data:text/html
URL

CVE-2017-5434: Use-after-free during focus handling

CVE-2017-5432: Use-after-free in text input selection

CVE-2017-5460: Use-after-free in frame selection

CVE-2017-5438: Use-after-free in nsAutoPtr during XSLT processing

CVE-2017-5439: Use-after-free in nsTArray Length() during XSLT
processing

CVE-2017-5440: Use-after-free in txExecutionState destructor during
XSLT processing

CVE-2017-5441: Use-after-free with selection during scroll events

CVE-2017-5442: Use-after-free during style changes

CVE-2017-5464: Memory corruption with accessibility and DOM
manipulation

CVE-2017-5443: Out-of-bounds write during BinHex decoding

CVE-2017-5444: Buffer overflow while parsing
application/http-index-format content

CVE-2017-5446: Out-of-bounds read when HTTP/2 DATA frames are sent
with incorrect data

CVE-2017-5447: Out-of-bounds read during glyph processing

CVE-2017-5465: Out-of-bounds read in ConvolvePixel

CVE-2017-5448: Out-of-bounds write in ClearKeyDecryptor

CVE-2017-5437: Vulnerabilities in Libevent library

CVE-2017-5454: Sandbox escape allowing file system read access through
file picker

CVE-2017-5455: Sandbox escape through internal feed reader APIs

CVE-2017-5456: Sandbox escape allowing local file system access

CVE-2017-5469: Potential Buffer overflow in flex-generated code

CVE-2017-5445: Uninitialized values used while parsing
application/http-index-format content

CVE-2017-5449: Crash during bidirectional unicode manipulation with
animation

CVE-2017-5450: Addressbar spoofing using javascript: URI on Firefox
for Android

CVE-2017-5451: Addressbar spoofing with onblur event

CVE-2017-5462: DRBG flaw in NSS

CVE-2017-5463: Addressbar spoofing through reader view on Firefox for
Android

CVE-2017-5467: Memory corruption when drawing Skia content

CVE-2017-5452: Addressbar spoofing during scrolling with editable
content on Firefox for Android

CVE-2017-5453: HTML injection into RSS Reader feed preview page
through TITLE element

CVE-2017-5458: Drag and drop of javascript: URLs can allow for
self-XSS

CVE-2017-5468: Incorrect ownership model for Private Browsing
information

CVE-2017-5430: Memory safety bugs fixed in Firefox 53 and Firefox ESR
52.1

CVE-2017-5429: Memory safety bugs fixed in Firefox 53, Firefox ESR
45.9, and Firefox ESR 52.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-10/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-11/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-12/"
  );
  # http://www.freebsd.org/ports/portaudit/5e0a038a-ca30-416d-a2f5-38cbf5e7df33.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2728a631"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<53.0_2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.50")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.50")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr>=46.0,1<52.1.0_2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<45.9.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox>=46.0,2<52.1.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<45.9.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul>=46.0<52.1.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<45.9.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird>=46.0<52.1.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<45.9.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird>=46.0<52.1.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<45.9.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
