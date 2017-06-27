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
  script_id(89048);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/19 14:02:54 $");

  script_cve_id("CVE-2016-2522", "CVE-2016-2523", "CVE-2016-2524", "CVE-2016-2525", "CVE-2016-2526", "CVE-2016-2527", "CVE-2016-2528", "CVE-2016-2529", "CVE-2016-2530", "CVE-2016-2531", "CVE-2016-2532", "CVE-2016-4415", "CVE-2016-4416", "CVE-2016-4417", "CVE-2016-4418", "CVE-2016-4419", "CVE-2016-4420", "CVE-2016-4421");

  script_name(english:"FreeBSD : wireshark -- multiple vulnerabilities (45117749-df55-11e5-b2bd-002590263bf5)");
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
"Wireshark development team reports :

The following vulnerabilities have been fixed :

- wnpa-sec-2016-02

ASN.1 BER dissector crash. (Bug 11828) CVE-2016-2522

- wnpa-sec-2016-03

DNP dissector infinite loop. (Bug 11938) CVE-2016-2523

- wnpa-sec-2016-04

X.509AF dissector crash. (Bug 12002) CVE-2016-2524

- wnpa-sec-2016-05

HTTP/2 dissector crash. (Bug 12077) CVE-2016-2525

- wnpa-sec-2016-06

HiQnet dissector crash. (Bug 11983) CVE-2016-2526

- wnpa-sec-2016-07

3GPP TS 32.423 Trace file parser crash. (Bug 11982)

CVE-2016-2527

- wnpa-sec-2016-08

LBMC dissector crash. (Bug 11984) CVE-2016-2528

- wnpa-sec-2016-09

iSeries file parser crash. (Bug 11985) CVE-2016-2529

- wnpa-sec-2016-10

RSL dissector crash. (Bug 11829) CVE-2016-2530 CVE-2016-2531

- wnpa-sec-2016-11

LLRP dissector crash. (Bug 12048) CVE-2016-2532

- wnpa-sec-2016-12

Ixia IxVeriWave file parser crash. (Bug 11795)

- wnpa-sec-2016-13

IEEE 802.11 dissector crash. (Bug 11818)

- wnpa-sec-2016-14

GSM A-bis OML dissector crash. (Bug 11825)

- wnpa-sec-2016-15

ASN.1 BER dissector crash. (Bug 12106)

- wnpa-sec-2016-16

SPICE dissector large loop. (Bug 12151)

- wnpa-sec-2016-17

NFS dissector crash.

- wnpa-sec-2016-18

ASN.1 BER dissector crash. (Bug 11822)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.2.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2016/05/01/1"
  );
  # http://www.freebsd.org/ports/portaudit/45117749-df55-11e5-b2bd-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b3f687c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tshark-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark-qt5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/01");
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

if (pkg_test(save_report:TRUE, pkg:"wireshark<2.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-lite<2.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-qt5<2.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark<2.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark-lite<2.0.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
