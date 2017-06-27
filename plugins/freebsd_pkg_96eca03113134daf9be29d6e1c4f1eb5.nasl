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
  script_id(97592);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/16 14:21:22 $");

  script_cve_id("CVE-2017-5398", "CVE-2017-5399", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5403", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5406", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5409", "CVE-2017-5410", "CVE-2017-5411", "CVE-2017-5412", "CVE-2017-5413", "CVE-2017-5414", "CVE-2017-5415", "CVE-2017-5416", "CVE-2017-5417", "CVE-2017-5418", "CVE-2017-5419", "CVE-2017-5420", "CVE-2017-5421", "CVE-2017-5422", "CVE-2017-5425", "CVE-2017-5426", "CVE-2017-5427");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (96eca031-1313-4daf-9be2-9d6e1c4f1eb5)");
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

CVE-2017-5400: asm.js JIT-spray bypass of ASLR and DEP

CVE-2017-5401: Memory Corruption when handling ErrorResult

CVE-2017-5402: Use-after-free working with events in FontFace objects

CVE-2017-5403: Use-after-free using addRange to add range to an
incorrect root object

CVE-2017-5404: Use-after-free working with ranges in selections

CVE-2017-5406: Segmentation fault in Skia with canvas operations

CVE-2017-5407: Pixel and history stealing via floating-point timing
side channel with SVG filters

CVE-2017-5410: Memory corruption during JavaScript garbage collection
incremental sweeping

CVE-2017-5411: Use-after-free in Buffer Storage in libGLES

CVE-2017-5409: File deletion via callback parameter in Mozilla Windows
Updater and Maintenance Service

CVE-2017-5408: Cross-origin reading of video captions in violation of
CORS

CVE-2017-5412: Buffer overflow read in SVG filters

CVE-2017-5413: Segmentation fault during bidirectional operations

CVE-2017-5414: File picker can choose incorrect default directory

CVE-2017-5415: Addressbar spoofing through blob URL

CVE-2017-5416: Null dereference crash in HttpChannel

CVE-2017-5417: Addressbar spoofing by draging and dropping URLs

CVE-2017-5425: Overly permissive Gecko Media Plugin sandbox regular
expression access

CVE-2017-5426: Gecko Media Plugin sandbox is not started if
seccomp-bpf filter is running

CVE-2017-5427: Non-existent chrome.manifest file loaded during startup

CVE-2017-5418: Out of bounds read when parsing HTTP digest
authorization responses

CVE-2017-5419: Repeated authentication prompts lead to DOS attack

CVE-2017-5420: Javascript: URLs can obfuscate addressbar location

CVE-2017-5405: FTP response codes can cause use of uninitialized
values for ports

CVE-2017-5421: Print preview spoofing

CVE-2017-5422: DOS attack by using view-source: protocol repeatedly in
one hyperlink

CVE-2017-5399: Memory safety bugs fixed in Firefox 52

CVE-2017-5398: Memory safety bugs fixed in Firefox 52 and Firefox ESR
45.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2017-05/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2017-06/"
  );
  # http://www.freebsd.org/ports/portaudit/96eca031-1313-4daf-9be2-9d6e1c4f1eb5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c3ab5f3"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/08");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<52.0_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.49")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.49")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr>=46.0,1<52.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<45.8.0_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox>=46.0,2<52.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<45.8.0_1,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul>=46.0<52.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<45.8.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird>=46.0<52.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<45.8.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird>=46.0<52.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<45.8.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
