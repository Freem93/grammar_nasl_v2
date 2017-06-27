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
  script_id(93614);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/10/28 21:03:37 $");

  script_cve_id("CVE-2016-2827", "CVE-2016-5256", "CVE-2016-5257", "CVE-2016-5270", "CVE-2016-5271", "CVE-2016-5272", "CVE-2016-5273", "CVE-2016-5274", "CVE-2016-5275", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5279", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5282", "CVE-2016-5283", "CVE-2016-5284");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (2c57c47e-8bb3-4694-83c8-9fc3abad3964)");
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

CVE-2016-2827 - Out-of-bounds read in
mozilla::net::IsValidReferrerPolicy [low]

CVE-2016-5256 - Memory safety bugs fixed in Firefox 49 [critical]

CVE-2016-5257 - Memory safety bugs fixed in Firefox 49 and Firefox ESR
45.4 [critical]

CVE-2016-5270 - Heap-buffer-overflow in
nsCaseTransformTextRunFactory::TransformString [high]

CVE-2016-5271 - Out-of-bounds read in
PropertyProvider::GetSpacingInternal [low]

CVE-2016-5272 - Bad cast in nsImageGeometryMixin [high]

CVE-2016-5273 - crash in
mozilla::a11y::HyperTextAccessible::GetChildOffset [high]

CVE-2016-5274 - use-after-free in nsFrameManager::CaptureFrameState
[high]

CVE-2016-5275 - global-buffer-overflow in
mozilla::gfx::FilterSupport::ComputeSourceNeededRegions [critical]

CVE-2016-5276 - Heap-use-after-free in
mozilla::a11y::DocAccessible::ProcessInvalidationList [high]

CVE-2016-5277 - Heap-use-after-free in nsRefreshDriver::Tick [high]

CVE-2016-5278 - Heap-buffer-overflow in nsBMPEncoder::AddImageFrame
[critical]

CVE-2016-5279 - Full local path of files is available to web pages
after drag and drop [moderate]

CVE-2016-5280 - Use-after-free in
mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap [high]

CVE-2016-5281 - use-after-free in DOMSVGLength [high]

CVE-2016-5282 - Don't allow content to request favicons from
non-whitelisted schemes [moderate]

CVE-2016-5283 - <iframe src> fragment timing attack can reveal
cross-origin data [high]

CVE-2016-5284 - Add-on update site certificate pin expiration [high]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-85/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-86/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2016-88/"
  );
  # http://www.freebsd.org/ports/portaudit/2c57c47e-8bb3-4694-83c8-9fc3abad3964.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aab88106"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/21");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<49.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.46")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.46")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<45.4.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<45.4.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<45.4.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<45.4.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<45.4.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
