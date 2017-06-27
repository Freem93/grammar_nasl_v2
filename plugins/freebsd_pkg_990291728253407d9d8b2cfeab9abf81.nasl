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
  script_id(81588);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/28 17:02:45 $");

  script_cve_id("CVE-2015-0819", "CVE-2015-0820", "CVE-2015-0821", "CVE-2015-0822", "CVE-2015-0823", "CVE-2015-0824", "CVE-2015-0825", "CVE-2015-0826", "CVE-2015-0827", "CVE-2015-0828", "CVE-2015-0829", "CVE-2015-0830", "CVE-2015-0831", "CVE-2015-0832", "CVE-2015-0833", "CVE-2015-0834", "CVE-2015-0835", "CVE-2015-0836");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (99029172-8253-407d-9d8b-2cfeab9abf81)");
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

MFSA-2015-11 Miscellaneous memory safety hazards (rv:36.0 / rv:31.5)

MFSA-2015-12 Invoking Mozilla updater will load locally stored DLL
files

MFSA-2015-13 Appended period to hostnames can bypass HPKP and HSTS
protections

MFSA-2015-14 Malicious WebGL content crash when writing strings

MFSA-2015-15 TLS TURN and STUN connections silently fail to simple TCP
connections

MFSA-2015-16 Use-after-free in IndexedDB

MFSA-2015-17 Buffer overflow in libstagefright during MP4 video
playback

MFSA-2015-18 Double-free when using non-default memory allocators with
a zero-length XHR

MFSA-2015-19 Out-of-bounds read and write while rendering SVG content

MFSA-2015-20 Buffer overflow during CSS restyling

MFSA-2015-21 Buffer underflow during MP3 playback

MFSA-2015-22 Crash using DrawTarget in Cairo graphics library

MFSA-2015-23 Use-after-free in Developer Console date with OpenType
Sanitiser

MFSA-2015-24 Reading of local files through manipulation of form
autocomplete

MFSA-2015-25 Local files or privileged URLs in pages can be opened
into new tabs

MFSA-2015-26 UI Tour whitelisted sites in background tab can spoof
foreground tabs

MFSA-2015-27 Caja Compiler JavaScript sandbox bypass"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-11/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-12/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-13/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-14/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-15/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-16/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-17/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-18/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-19/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-20/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-21/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-22/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-23/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-24/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-25/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-26/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-27/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/"
  );
  # http://www.freebsd.org/ports/portaudit/99029172-8253-407d-9d8b-2cfeab9abf81.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abff0cd3"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<36.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<31.5.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<36.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.33")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<31.5.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.33")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<31.5.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<31.5.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
