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
  script_id(96820);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/03/20 15:44:32 $");

  script_cve_id("CVE-2017-2020", "CVE-2017-2021", "CVE-2017-2022", "CVE-2017-2023", "CVE-2017-2024", "CVE-2017-2025", "CVE-2017-2026", "CVE-2017-5006", "CVE-2017-5007", "CVE-2017-5008", "CVE-2017-5009", "CVE-2017-5010", "CVE-2017-5011", "CVE-2017-5012", "CVE-2017-5013", "CVE-2017-5014", "CVE-2017-5015", "CVE-2017-5016", "CVE-2017-5017", "CVE-2017-5018", "CVE-2017-5019");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (4b9ca994-e3d9-11e6-813d-e8e0b747a45a)");
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

51 security fixes in this release, including :

- [671102] High CVE-2017-5007: Universal XSS in Blink. Credit to
Mariusz Mlynski

- [673170] High CVE-2017-5006: Universal XSS in Blink. Credit to
Mariusz Mlynski

- [668552] High CVE-2017-5008: Universal XSS in Blink. Credit to
Mariusz Mlynski

- [663476] High CVE-2017-5010: Universal XSS in Blink. Credit to
Mariusz Mlynski

- [662859] High CVE-2017-5011: Unauthorised file access in Devtools.
Credit to Khalil Zhani

- [667504] High CVE-2017-5009: Out of bounds memory access in WebRTC.
Credit to Sean Stanek and Chip Bradford

- [681843] High CVE-2017-5012: Heap overflow in V8. Credit to Gergely
Nagy (Tresorit)

- [677716] Medium CVE-2017-5013: Address spoofing in Omnibox. Credit
to Haosheng Wang (@gnehsoah)

- [675332] Medium CVE-2017-5014: Heap overflow in Skia. Credit to
sweetchip

- [673971] Medium CVE-2017-5015: Address spoofing in Omnibox. Credit
to Armin Razmdjou

- [666714] Medium CVE-2017-5019: Use after free in Renderer. Credit to
Wadih Matar

- [673163] Medium CVE-2017-5016: UI spoofing in Blink. Credit to
Haosheng Wang (@gnehsoah)

- [676975] Medium CVE-2017-5017: Uninitialised memory access in webm
video. Credit to danberm

- [668665] Medium CVE-2017-5018: Universal XSS in chrome://apps.
Credit to Rob Wu

- [668653] Medium CVE-2017-5020: Universal XSS in chrome://downloads.
Credit to Rob Wu

- [663726] Low CVE-2017-5021: Use after free in Extensions. Credit to
Rob Wu

- [663620] Low CVE-2017-5022: Bypass of Content Security Policy in
Blink. Credit to Pujun Li of PKAV Team

- [651443] Low CVE-2017-5023: Type confunsion in metrics. Credit to
the UK's National Cyber Security Centre (NCSC)

- [643951] Low CVE-2017-5024: Heap overflow in FFmpeg. Credit to Paul
Mehta

- [643950] Low CVE-2017-5025: Heap overflow in FFmpeg. Credit to Paul
Mehta

- [634108] Low CVE-2017-5026: UI spoofing. Credit to Ronni Skansing

- [685349] Various fixes from internal audits, fuzzing and other
initiatives"
  );
  # https://chromereleases.googleblog.com/2017/01/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fcdefa5b"
  );
  # http://www.freebsd.org/ports/portaudit/4b9ca994-e3d9-11e6-813d-e8e0b747a45a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ac81041"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/27");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<56.0.2924.76")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<56.0.2924.76")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<56.0.2924.76")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
