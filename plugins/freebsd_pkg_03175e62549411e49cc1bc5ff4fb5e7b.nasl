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
  script_id(78495);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3568");
  script_bugtraq_id(70574, 70584, 70585, 70586);
  script_xref(name:"FreeBSD", value:"SA-14:23.openssl");

  script_name(english:"FreeBSD : OpenSSL -- multiple vulnerabilities (03175e62-5494-11e4-9cc1-bc5ff4fb5e7b) (POODLE)");
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

A flaw in the DTLS SRTP extension parsing code allows an attacker, who
sends a carefully crafted handshake message, to cause OpenSSL to fail
to free up to 64k of memory causing a memory leak. This could be
exploited in a Denial Of Service attack. This issue affects OpenSSL
1.0.1 server implementations for both SSL/TLS and DTLS regardless of
whether SRTP is used or configured. Implementations of OpenSSL that
have been compiled with OPENSSL_NO_SRTP defined are not affected.
[CVE-2014-3513].

When an OpenSSL SSL/TLS/DTLS server receives a session ticket the
integrity of that ticket is first verified. In the event of a session
ticket integrity check failing, OpenSSL will fail to free memory
causing a memory leak. By sending a large number of invalid session
tickets an attacker could exploit this issue in a Denial Of Service
attack. [CVE-2014-3567].

OpenSSL has added support for TLS_FALLBACK_SCSV to allow applications
to block the ability for a MITM attacker to force a protocol
downgrade.

Some client applications (such as browsers) will reconnect using a
downgraded protocol to work around interoperability bugs in older
servers. This could be exploited by an active man-in-the-middle to
downgrade connections to SSL 3.0 even if both sides of the connection
support higher protocols. SSL 3.0 contains a number of weaknesses
including POODLE [CVE-2014-3566].

When OpenSSL is configured with 'no-ssl3' as a build option, servers
could accept and complete a SSL 3.0 handshake, and clients could be
configured to send them. [CVE-2014-3568]."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20141015.txt"
  );
  # http://www.freebsd.org/ports/portaudit/03175e62-5494-11e4-9cc1-bc5ff4fb5e7b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62e84c95"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mingw32-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");
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

if (pkg_test(save_report:TRUE, pkg:"openssl>=1.0.1<1.0.1_16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mingw32-openssl>=1.0.1<1.0.1j")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-openssl<1.0.1e_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
