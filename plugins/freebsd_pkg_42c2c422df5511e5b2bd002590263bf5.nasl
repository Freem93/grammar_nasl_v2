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

include("compat.inc");

if (description)
{
  script_id(89047);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/01 14:49:47 $");

  script_name(english:"FreeBSD : wireshark -- multiple vulnerabilities (42c2c422-df55-11e5-b2bd-002590263bf5)");
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

- wnpa-sec-2015-31

NBAP dissector crashes. (Bug 11602, Bug 11835, Bug 11841)

- wnpa-sec-2015-37

NLM dissector crash.

- wnpa-sec-2015-39

BER dissector crash.

- wnpa-sec-2015-40

Zlib decompression crash. (Bug 11548)

- wnpa-sec-2015-41

SCTP dissector crash. (Bug 11767)

- wnpa-sec-2015-42

802.11 decryption crash. (Bug 11790, Bug 11826)

- wnpa-sec-2015-43

DIAMETER dissector crash. (Bug 11792)

- wnpa-sec-2015-44

VeriWave file parser crashes. (Bug 11789, Bug 11791)

- wnpa-sec-2015-45

RSVP dissector crash. (Bug 11793)

- wnpa-sec-2015-46

ANSI A and GSM A dissector crashes. (Bug 11797)

- wnpa-sec-2015-47

Ascend file parser crash. (Bug 11794)

- wnpa-sec-2015-48

NBAP dissector crash. (Bug 11815)

- wnpa-sec-2015-49

RSL dissector crash. (Bug 11829)

- wnpa-sec-2015-50

ZigBee ZCL dissector crash. (Bug 11830)

- wnpa-sec-2015-51

Sniffer file parser crash. (Bug 11827)

- wnpa-sec-2015-52

NWP dissector crash. (Bug 11726)

- wnpa-sec-2015-53

BT ATT dissector crash. (Bug 11817)

- wnpa-sec-2015-54

MP2T file parser crash. (Bug 11820)

- wnpa-sec-2015-55

MP2T file parser crash. (Bug 11821)

- wnpa-sec-2015-56

S7COMM dissector crash. (Bug 11823)

- wnpa-sec-2015-57

IPMI dissector crash. (Bug 11831)

- wnpa-sec-2015-58

TDS dissector crash. (Bug 11846)

- wnpa-sec-2015-59

PPI dissector crash. (Bug 11876)

- wnpa-sec-2015-60

MS-WSP dissector crash. (Bug 11931)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.1.html"
  );
  # http://www.freebsd.org/ports/portaudit/42c2c422-df55-11e5-b2bd-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3caa121f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tshark-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark-qt5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/29");
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

if (pkg_test(save_report:TRUE, pkg:"wireshark<2.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-lite<2.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-qt5<2.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark<2.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark-lite<2.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
