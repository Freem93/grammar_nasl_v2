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
  script_id(88465);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/10/19 14:02:54 $");

  script_cve_id("CVE-2015-3197", "CVE-2016-0701");
  script_xref(name:"FreeBSD", value:"SA-16:11.openssl");

  script_name(english:"FreeBSD : openssl -- multiple vulnerabilities (3679fd10-c5d1-11e5-b85f-0018fe623f2b)");
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
"OpenSSL project reports :

- Historically OpenSSL only ever generated DH parameters based on
'safe' primes. More recently (in version 1.0.2) support was provided
for generating X9.42 style parameter files such as those required for
RFC 5114 support. The primes used in such files may not be 'safe'.
Where an application is using DH configured with parameters based on
primes that are not 'safe' then an attacker could use this fact to
find a peer's private DH exponent. This attack requires that the
attacker complete multiple handshakes in which the peer uses the same
private DH exponent. For example this could be used to discover a TLS
server's private DH exponent if it's reusing the private DH exponent
or it's using a static DH ciphersuite. OpenSSL provides the option
SSL_OP_SINGLE_DH_USE for ephemeral DH (DHE) in TLS. It is not on by
default. If the option is not set then the server reuses the same
private DH exponent for the life of the server process and would be
vulnerable to this attack. It is believed that many popular
applications do set this option and would therefore not be at risk.
(CVE-2016-0701)

- A malicious client can negotiate SSLv2 ciphers that have been
disabled on the server and complete SSLv2 handshakes even if all SSLv2
ciphers have been disabled, provided that the SSLv2 protocol was not
also disabled via SSL_OP_NO_SSLv2. (CVE-2015-3197)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20160128.txt"
  );
  # http://www.freebsd.org/ports/portaudit/3679fd10-c5d1-11e5-b85f-0018fe623f2b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5e5ddf4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mingw32-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/29");
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

if (pkg_test(save_report:TRUE, pkg:"openssl<1.0.2_7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mingw32-openssl>=1.0.1<1.0.2f")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
