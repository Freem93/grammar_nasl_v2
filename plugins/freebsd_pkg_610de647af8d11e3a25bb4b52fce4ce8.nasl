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
  script_id(73111);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/01/06 15:36:33 $");

  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1496", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1501", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1506", "CVE-2014-1507", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (610de647-af8d-11e3-a25b-b4b52fce4ce8)");
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

MFSA 2014-15 Miscellaneous memory safety hazards (rv:28.0 / rv:24.4)

MFSA 2014-16 Files extracted during updates are not always read only

MFSA 2014-17 Out of bounds read during WAV file decoding

MFSA 2014-18 crypto.generateCRMFRequest does not validate type of key

MFSA 2014-19 Spoofing attack on WebRTC permission prompt

MFSA 2014-20 onbeforeunload and JavaScript navigation DOS

MFSA 2014-21 Local file access via Open Link in new tab

MFSA 2014-22 WebGL content injection from one domain to rendering in
another

MFSA 2014-23 Content Security Policy for data: documents not preserved
by session restore

MFSA 2014-24 Android Crash Reporter open to manipulation

MFSA 2014-25 Firefox OS DeviceStorageFile object vulnerable to
relative path escape

MFSA 2014-26 Information disclosure through polygon rendering in
MathML

MFSA 2014-27 Memory corruption in Cairo during PDF font rendering

MFSA 2014-28 SVG filters information disclosure through
feDisplacementMap

MFSA 2014-29 Privilege escalation using WebIDL-implemented APIs

MFSA 2014-30 Use-after-free in TypeObject

MFSA 2014-31 Out-of-bounds read/write through neutering ArrayBuffer
objects

MFSA 2014-32 Out-of-bounds write through TypedArrayObject after
neutering"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-24.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-27.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-31.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-32.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-vulnerabilities/"
  );
  # http://www.freebsd.org/ports/portaudit/610de647-af8d-11e3-a25b-b4b52fce4ce8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b81df8d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox WebIDL Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<28.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<24.4.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<28.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.25")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<24.4.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.25")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<24.4.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
