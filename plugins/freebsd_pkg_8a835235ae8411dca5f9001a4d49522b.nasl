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
  script_id(29772);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/08 20:42:12 $");

  script_cve_id("CVE-2007-6112", "CVE-2007-6113", "CVE-2007-6114", "CVE-2007-6115", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6120", "CVE-2007-6121", "CVE-2007-6438", "CVE-2007-6439", "CVE-2007-6441", "CVE-2007-6450", "CVE-2007-6451");

  script_name(english:"FreeBSD : wireshark -- multiple vulnerabilities (8a835235-ae84-11dc-a5f9-001a4d49522b)");
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
"The Wireshark team reports of multiple vulnerabilities :

- Wireshark could crash when reading an MP3 file.

- Beyond Security discovered that Wireshark could loop excessively
while reading a malformed DNP packet.

- Stefan Esser discovered a buffer overflow in the SSL dissector.

- The ANSI MAP dissector could be susceptible to a buffer overflow on
some platforms.

- The Firebird/Interbase dissector could go into an infinite loop or
crash.

- The NCP dissector could cause a crash.

- The HTTP dissector could crash on some systems while decoding
chunked messages.

- The MEGACO dissector could enter a large loop and consume system
resources.

- The DCP ETSI dissector could enter a large loop and consume system
resources.

- Fabiodds discovered a buffer overflow in the iSeries (OS/400)
Communication trace file parser.

- The PPP dissector could overflow a buffer.

- The Bluetooth SDP dissector could go into an infinite loop.

- A malformed RPC Portmap packet could cause a crash.

- The IPv6 dissector could loop excessively.

- The USB dissector could loop excessively or crash.

- The SMB dissector could crash.

- The RPL dissector could go into an infinite loop.

- The WiMAX dissector could crash due to unaligned access on some
platforms.

- The CIP dissector could attempt to allocate a huge amount of memory
and crash. Impact It may be possible to make Wireshark or Ethereal
crash or use up available memory by injecting a purposefully malformed
packet onto the wire or by convincing someone to read a malformed
packet trace file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2007-03.html"
  );
  # http://www.freebsd.org/ports/portaudit/8a835235-ae84-11dc-a5f9-001a4d49522b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37f653a8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ethereal-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tethereal-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"wireshark>=0.8.16<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-lite>=0.8.16<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ethereal>=0.8.16<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ethereal-lite>=0.8.16<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tethereal>=0.8.16<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tethereal-lite>=0.8.16<0.99.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
