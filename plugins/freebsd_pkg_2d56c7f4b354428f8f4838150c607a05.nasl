#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
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
  script_id(86079);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/11/08 16:01:24 $");

  script_cve_id("CVE-2015-4476", "CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4502", "CVE-2015-4503", "CVE-2015-4504", "CVE-2015-4505", "CVE-2015-4506", "CVE-2015-4507", "CVE-2015-4508", "CVE-2015-4509", "CVE-2015-4510", "CVE-2015-4512", "CVE-2015-4516", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7178", "CVE-2015-7179", "CVE-2015-7180");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (2d56c7f4-b354-428f-8f48-38150c607a05)");
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

MFSA 2015-96 Miscellaneous memory safety hazards (rv:41.0 / rv:38.3)

MFSA 2015-97 Memory leak in mozTCPSocket to servers

MFSA 2015-98 Out of bounds read in QCMS library with ICC V4 profile
attributes

MFSA 2015-99 Site attribute spoofing on Android by pasting URL with
unknown scheme

MFSA 2015-100 Arbitrary file manipulation by local user through
Mozilla updater

MFSA 2015-101 Buffer overflow in libvpx while parsing vp9 format video

MFSA 2015-102 Crash when using debugger with SavedStacks in JavaScript

MFSA 2015-103 URL spoofing in reader mode

MFSA 2015-104 Use-after-free with shared workers and IndexedDB

MFSA 2015-105 Buffer overflow while decoding WebM video

MFSA 2015-106 Use-after-free while manipulating HTML media content

MFSA 2015-107 Out-of-bounds read during 2D canvas display on Linux
16-bit color depth systems

MFSA 2015-108 Scripted proxies can access inner window

MFSA 2015-109 JavaScript immutable property enforcement can be
bypassed

MFSA 2015-110 Dragging and dropping images exposes final URL after
redirects

MFSA 2015-111 Errors in the handling of CORS preflight request headers

MFSA 2015-112 Vulnerabilities found through code inspection

MFSA 2015-113 Memory safety errors in libGLES in the ANGLE graphics
library

MFSA 2015-114 Information disclosure via the High Resolution Time API"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-96/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-97/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-98/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-99/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-100/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-101/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-102/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-103/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-104/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-105/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-106/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-107/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-108/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-109/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-110/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-111/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-112/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-113/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-114/"
  );
  # http://www.freebsd.org/ports/portaudit/2d56c7f4-b354-428f-8f48-38150c607a05.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bc9f1df"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<41.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<41.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.38")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.38")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<38.3.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<38.3.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<38.3.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<38.3.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
