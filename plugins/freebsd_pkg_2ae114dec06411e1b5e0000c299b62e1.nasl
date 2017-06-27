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
  script_id(59747);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/09 15:44:46 $");

  script_cve_id("CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4619", "CVE-2012-0884", "CVE-2012-2110");
  script_bugtraq_id(51281, 52428, 53158);
  script_osvdb_id(78187, 78188, 78190, 80039, 81223);
  script_xref(name:"FreeBSD", value:"SA-12:01.openssl");

  script_name(english:"FreeBSD : FreeBSD -- OpenSSL multiple vulnerabilities (2ae114de-c064-11e1-b5e0-000c299b62e1)");
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
"Problem description :

OpenSSL fails to clear the bytes used as block cipher padding in SSL
3.0 records when operating as a client or a server that accept SSL 3.0
handshakes. As a result, in each record, up to 15 bytes of
uninitialized memory may be sent, encrypted, to the SSL peer. This
could include sensitive contents of previously freed memory.
[CVE-2011-4576]

OpenSSL support for handshake restarts for server gated cryptography
(SGC) can be used in a denial-of-service attack. [CVE-2011-4619]

If an application uses OpenSSL's certificate policy checking when
verifying X509 certificates, by enabling the X509_V_FLAG_POLICY_CHECK
flag, a policy check failure can lead to a double-free.
[CVE-2011-4109]

A weakness in the OpenSSL PKCS #7 code can be exploited using
Bleichenbacher's attack on PKCS #1 v1.5 RSA padding also known as the
million message attack (MMA). [CVE-2012-0884]

The asn1_d2i_read_bio() function, used by the d2i_*_bio and d2i_*_fp
functions, in OpenSSL contains multiple integer errors that can cause
memory corruption when parsing encoded ASN.1 data. This error can
occur on systems that parse untrusted ASN.1 data, such as X.509
certificates or RSA public keys. [CVE-2012-2110]"
  );
  # http://www.freebsd.org/ports/portaudit/2ae114de-c064-11e1-b5e0-000c299b62e1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eadc84df"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:FreeBSD");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;

if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=7.4<7.4_8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=8.1<8.1_10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=8.2<8.2_8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=8.3<8.3_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=9.0<9.0_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
