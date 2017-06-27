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
  script_id(77036);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/08/10 13:36:30 $");

  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511", "CVE-2014-3512", "CVE-2014-5139");
  script_bugtraq_id(69075, 69076, 69077, 69078, 69079, 69082, 69083, 69084);
  script_xref(name:"FreeBSD", value:"SA-14:18.openssl");

  script_name(english:"FreeBSD : OpenSSL -- multiple vulnerabilities (8aff07eb-1dbd-11e4-b6ba-3c970e169bc2)");
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
"The OpenSSL Project reports :

A flaw in OBJ_obj2txt may cause pretty printing functions such as
X509_name_oneline, X509_name_print_ex et al. to leak some information
from the stack. [CVE-2014-3508]

The issue affects OpenSSL clients and allows a malicious server to
crash the client with a NULL pointer dereference (read) by specifying
an SRP ciphersuite even though it was not properly negotiated with the
client. [CVE-2014-5139]

If a multithreaded client connects to a malicious server using a
resumed session and the server sends an ec point format extension it
could write up to 255 bytes to freed memory. [CVE-2014-3509]

An attacker can force an error condition which causes openssl to crash
whilst processing DTLS packets due to memory being freed twice. This
can be exploited through a Denial of Service attack. [CVE-2014-3505]

An attacker can force openssl to consume large amounts of memory
whilst processing DTLS handshake messages. This can be exploited
through a Denial of Service attack. [CVE-2014-3506]

By sending carefully crafted DTLS packets an attacker could cause
openssl to leak memory. This can be exploited through a Denial of
Service attack. [CVE-2014-3507]

OpenSSL DTLS clients enabling anonymous (EC)DH ciphersuites are
subject to a denial of service attack. A malicious server can crash
the client with a NULL pointer dereference (read) by specifying an
anonymous (EC)DH ciphersuite and sending carefully crafted handshake
messages. [CVE-2014-3510]

A flaw in the OpenSSL SSL/TLS server code causes the server to
negotiate TLS 1.0 instead of higher protocol versions when the
ClientHello message is badly fragmented. This allows a
man-in-the-middle attacker to force a downgrade to TLS 1.0 even if
both the server and the client support a higher protocol version, by
modifying the client's TLS records. [CVE-2014-3511]

A malicious client or server can send invalid SRP parameters and
overrun an internal buffer. Only applications which are explicitly set
up for SRP use are affected. [CVE-2014-3512]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20140806.txt"
  );
  # http://www.freebsd.org/ports/portaudit/8aff07eb-1dbd-11e4-b6ba-3c970e169bc2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?816f8443"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mingw32-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");
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

if (pkg_test(save_report:TRUE, pkg:"openssl>=1.0.1<1.0.1_14")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mingw32-openssl>=1.0.1<1.0.1i")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
