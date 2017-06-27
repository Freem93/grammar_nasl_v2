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
  script_id(97689);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id("CVE-2017-5029", "CVE-2017-5030", "CVE-2017-5031", "CVE-2017-5032", "CVE-2017-5033", "CVE-2017-5034", "CVE-2017-5035", "CVE-2017-5036", "CVE-2017-5037", "CVE-2017-5038", "CVE-2017-5039", "CVE-2017-5040", "CVE-2017-5041", "CVE-2017-5042", "CVE-2017-5043", "CVE-2017-5044", "CVE-2017-5045", "CVE-2017-5046");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (a505d397-0758-11e7-8d8b-e8e0b747a45a)");
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

36 security fixes in this release, including :

- [682194] High CVE-2017-5030: Memory corruption in V8. Credit to
Brendon Tiszka

- [682020] High CVE-2017-5031: Use after free in ANGLE. Credit to
Looben Yang

- [668724] High CVE-2017-5032: Out of bounds write in PDFium. Credit
to Ashfaq Ansari - Project Srishti

- [676623] High CVE-2017-5029: Integer overflow in libxslt. Credit to
Holger Fuhrmannek

- [678461] High CVE-2017-5034: Use after free in PDFium. Credit to Ke
Liu of Tencent's Xuanwu Lab

- [688425] High CVE-2017-5035: Incorrect security UI in Omnibox.
Credit to Enzo Aguado

- [691371] High CVE-2017-5036: Use after free in PDFium. Credit to
Anonymous

- [679640] High CVE-2017-5037: Multiple out of bounds writes in
ChunkDemuxer. Credit to Yongke Wang of Tecent's Xuanwu Lab

- [679649] High CVE-2017-5039: Use after free in PDFium. Credit to
jinmo123

- [691323] Medium CVE-2017-5040: Information disclosure in V8. Credit
to Choongwoo Han

- [642490] Medium CVE-2017-5041: Address spoofing in Omnibox. Credit
to Jordi Chancel

- [669086] Medium CVE-2017-5033: Bypass of Content Security Policy in
Blink. Credit to Nicolai Grodum

- [671932] Medium CVE-2017-5042: Incorrect handling of cookies in
Cast. Credit to Mike Ruddy

- [695476] Medium CVE-2017-5038: Use after free in GuestView. Credit
to Anonymous

- [683523] Medium CVE-2017-5043: Use after free in GuestView. Credit
to Anonymous

- [688987] Medium CVE-2017-5044: Heap overflow in Skia. Credit to
Kushal Arvind Shah of Fortinet's FortiGuard Labs

- [667079] Medium CVE-2017-5045: Information disclosure in XSS
Auditor. Credit to Dhaval Kapil

- [680409] Medium CVE-2017-5046: Information disclosure in Blink.
Credit to Masato Kinugawa

- [699618] Various fixes from internal audits, fuzzing and other
initiatives"
  );
  # https://chromereleases.googleblog.com/2017/03/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d061769"
  );
  # http://www.freebsd.org/ports/portaudit/a505d397-0758-11e7-8d8b-e8e0b747a45a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b463390"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/13");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<57.0.2987.98")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<57.0.2987.98")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<57.0.2987.98")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
