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
  script_id(92921);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:02:54 $");

  script_cve_id("CVE-2016-0702", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-0800");
  script_xref(name:"FreeBSD", value:"SA-16:12.openssl");

  script_name(english:"FreeBSD : FreeBSD -- Multiple OpenSSL vulnerabilities (7b1a4a27-600a-11e6-a6c3-14dae9d210b8) (DROWN)");
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
"A cross-protocol attack was discovered that could lead to decryption
of TLS sessions by using a server supporting SSLv2 and EXPORT cipher
suites as a Bleichenbacher RSA padding oracle. Note that traffic
between clients and non-vulnerable servers can be decrypted provided
another server supporting SSLv2 and EXPORT ciphers (even with a
different protocol such as SMTP, IMAP or POP3) shares the RSA keys of
the non-vulnerable server. This vulnerability is known as DROWN.
[CVE-2016-0800]

A double free bug was discovered when OpenSSL parses malformed DSA
private keys and could lead to a DoS attack or memory corruption for
applications that receive DSA private keys from untrusted sources.
This scenario is considered rare. [CVE-2016-0705]

The SRP user database lookup method SRP_VBASE_get_by_user had
confusing memory management semantics; the returned pointer was
sometimes newly allocated, and sometimes owned by the callee. The
calling code has no way of distinguishing these two cases.
[CVE-2016-0798]

In the BN_hex2bn function, the number of hex digits is calculated
using an int value |i|. Later |bn_expand| is called with a value of |i
* 4|. For large values of |i| this can result in |bn_expand| not
allocating any memory because |i * 4| is negative. This can leave the
internal BIGNUM data field as NULL leading to a subsequent NULL
pointer dereference. For very large values of |i|, the calculation |i
* 4| could be a positive value smaller than |i|. In this case memory
is allocated to the internal BIGNUM data field, but it is
insufficiently sized leading to heap corruption. A similar issue
exists in BN_dec2bn. This could have security consequences if
BN_hex2bn/BN_dec2bn is ever called by user applications with very
large untrusted hex/dec data. This is anticipated to be a rare
occurrence. [CVE-2016-0797]

The internal |fmtstr| function used in processing a '%s' formatted
string in the BIO_*printf functions could overflow while calculating
the length of a string and cause an out-of-bounds read when printing
very long strings. [CVE-2016-0799]

A side-channel attack was found which makes use of cache-bank
conflicts on the Intel Sandy-Bridge microarchitecture which could lead
to the recovery of RSA keys. [CVE-2016-0702]

s2_srvr.c did not enforce that clear-key-length is 0 for non-export
ciphers. If clear-key bytes are present for these ciphers, they
displace encrypted-key bytes. [CVE-2016-0703]

s2_srvr.c overwrites the wrong bytes in the master key when applying
Bleichenbacher protection for export cipher suites. [CVE-2016-0704]
Impact : Servers that have SSLv2 protocol enabled are vulnerable to
the 'DROWN' attack which allows a remote attacker to fast attack many
recorded TLS connections made to the server, even when the client did
not make any SSLv2 connections themselves.

An attacker who can supply malformed DSA private keys to OpenSSL
applications may be able to cause memory corruption which would lead
to a Denial of Service condition. [CVE-2016-0705]

An attacker connecting with an invalid username can cause memory leak,
which could eventually lead to a Denial of Service condition.
[CVE-2016-0798]

An attacker who can inject malformed data into an application may be
able to cause memory corruption which would lead to a Denial of
Service condition. [CVE-2016-0797, CVE-2016-0799]

A local attacker who has control of code in a thread running on the
same hyper-threaded core as the victim thread which is performing
decryptions could recover RSA keys. [CVE-2016-0702]

An eavesdropper who can intercept SSLv2 handshake can conduct an
efficient divide-and-conquer key recovery attack and use the server as
an oracle to determine the SSLv2 master-key, using only 16 connections
to the server and negligible computation. [CVE-2016-0703]

An attacker can use the Bleichenbacher oracle, which enables more
efficient variant of the DROWN attack. [CVE-2016-0704]"
  );
  # http://www.freebsd.org/ports/portaudit/7b1a4a27-600a-11e6-a6c3-14dae9d210b8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bea3c88e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:FreeBSD");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.2<10.2_13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.1<10.1_30")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=9.3<9.3_38")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
