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
  script_id(96743);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/15 21:22:53 $");

  script_cve_id("CVE-2017-5373", "CVE-2017-5374", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5377", "CVE-2017-5378", "CVE-2017-5379", "CVE-2017-5380", "CVE-2017-5381", "CVE-2017-5382", "CVE-2017-5383", "CVE-2017-5384", "CVE-2017-5385", "CVE-2017-5386", "CVE-2017-5387", "CVE-2017-5388", "CVE-2017-5389", "CVE-2017-5390", "CVE-2017-5391", "CVE-2017-5392", "CVE-2017-5393", "CVE-2017-5394", "CVE-2017-5395", "CVE-2017-5396");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (e60169c4-aa86-46b0-8ae2-0d81f683df09)");
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

CVE-2017-5373: Memory safety bugs fixed in Firefox 51 and Firefox ESR
45.7

CVE-2017-5374: Memory safety bugs fixed in Firefox 51

CVE-2017-5375: Excessive JIT code allocation allows bypass of ASLR and
DEP

CVE-2017-5376: Use-after-free in XSL

CVE-2017-5377: Memory corruption with transforms to create gradients
in Skia

CVE-2017-5378: Pointer and frame data leakage of JavaScript objects

CVE-2017-5379: Use-after-free in Web Animations

CVE-2017-5380: Potential use-after-free during DOM manipulations

CVE-2017-5381: Certificate Viewer exporting can be used to navigate
and save to arbitrary filesystem locations

CVE-2017-5382: Feed preview can expose privileged content errors and
exceptions

CVE-2017-5383: Location bar spoofing with unicode characters

CVE-2017-5384: Information disclosure via Proxy Auto-Config (PAC)

CVE-2017-5385: Data sent in multipart channels ignores referrer-policy
response headers

CVE-2017-5386: WebExtensions can use data: protocol to affect other
extensions

CVE-2017-5387: Disclosure of local file existence through TRACK tag
error messages

CVE-2017-5388: WebRTC can be used to generate a large amount of UDP
traffic for DDOS attacks

CVE-2017-5389: WebExtensions can install additional add-ons via
modified host requests

CVE-2017-5390: Insecure communication methods in Developer Tools JSON
viewer

CVE-2017-5391: Content about: pages can load privileged about: pages

CVE-2017-5392: Weak references using multiple threads on weak proxy
objects lead to unsafe memory usage

CVE-2017-5393: Remove addons.mozilla.org CDN from whitelist for
mozAddonManager

CVE-2017-5394: Android location bar spoofing using fullscreen and
JavaScript events

CVE-2017-5395: Android location bar spoofing during scrolling

CVE-2017-5396: Use-after-free with Media Decoder"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2017-01/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2017-02/"
  );
  # http://www.freebsd.org/ports/portaudit/e60169c4-aa86-46b0-8ae2-0d81f683df09.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?719c04d0"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/25");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<51.0_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.48")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.48")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<45.7.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<45.7.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<45.7.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<45.7.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<45.7.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
