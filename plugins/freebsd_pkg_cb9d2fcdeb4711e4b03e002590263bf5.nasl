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

include("compat.inc");

if (description)
{
  script_id(83082);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/04/30 14:08:21 $");

  script_cve_id("CVE-2015-1863");

  script_name(english:"FreeBSD : wpa_supplicant -- P2P SSID processing vulnerability (cb9d2fcd-eb47-11e4-b03e-002590263bf5)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jouni Malinen reports :

A vulnerability was found in how wpa_supplicant uses SSID information
parsed from management frames that create or update P2P peer entries
(e.g., Probe Response frame or number of P2P Public Action frames).
SSID field has valid length range of 0-32 octets. However, it is
transmitted in an element that has a 8-bit length field and potential
maximum payload length of 255 octets. wpa_supplicant was not
sufficiently verifying the payload length on one of the code paths
using the SSID received from a peer device.

This can result in copying arbitrary data from an attacker to a fixed
length buffer of 32 bytes (i.e., a possible overflow of up to 223
bytes). The SSID buffer is within struct p2p_device that is allocated
from heap. The overflow can override couple of variables in the
struct, including a pointer that gets freed. In addition about 150
bytes (the exact length depending on architecture) can be written
beyond the end of the heap allocation.

This could result in corrupted state in heap, unexpected program
behavior due to corrupted P2P peer device information, denial of
service due to wpa_supplicant process crash, exposure of memory
contents during GO Negotiation, and potentially arbitrary code
execution.

Vulnerable versions/configurations

wpa_supplicant v1.0-v2.4 with CONFIG_P2P build option enabled (which
is not compiled by default).

Attacker (or a system controlled by the attacker) needs to be within
radio range of the vulnerable system to send a suitably constructed
management frame that triggers a P2P peer device information to be
created or updated.

The vulnerability is easiest to exploit while the device has started
an active P2P operation (e.g., has ongoing P2P_FIND or P2P_LISTEN
control interface command in progress). However, it may be possible,
though significantly more difficult, to trigger this even without any
active P2P operation in progress."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://w1.fi/security/2015-1/wpa_supplicant-p2p-ssid-overflow.txt"
  );
  # http://www.freebsd.org/ports/portaudit/cb9d2fcd-eb47-11e4-b03e-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b91cc7f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/27");
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

if (pkg_test(save_report:TRUE, pkg:"wpa_supplicant<2.4_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
