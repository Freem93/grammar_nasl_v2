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
  script_id(21435);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/09/02 14:18:43 $");

  script_cve_id("CVE-2005-2969");
  script_osvdb_id(19919);
  script_xref(name:"FreeBSD", value:"SA-05:21.openssl");

  script_name(english:"FreeBSD : openssl -- potential SSL 2.0 rollback (60e26a40-3b25-11da-9484-00123ffe8333)");
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
"Vulnerability :

Such applications are affected if they use the option
SSL_OP_MSIE_SSLV2_RSA_PADDING. This option is implied by use of
SSL_OP_ALL, which is intended to work around various bugs in
third-party software that might prevent interoperability. The
SSL_OP_MSIE_SSLV2_RSA_PADDING option disables a verification step in
the SSL 2.0 server supposed to prevent active protocol-version
rollback attacks. With this verification step disabled, an attacker
acting as a 'man in the middle' can force a client and a server to
negotiate the SSL 2.0 protocol even if these parties both support SSL
3.0 or TLS 1.0. The SSL 2.0 protocol is known to have severe
cryptographic weaknesses and is supported as a fallback only.

Applications using neither SSL_OP_MSIE_SSLV2_RSA_PADDING nor
SSL_OP_ALL are not affected. Also, applications that disable use of
SSL 2.0 are not affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/secadv/20051011.txt"
  );
  # http://www.freebsd.org/ports/portaudit/60e26a40-3b25-11da-9484-00123ffe8333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8291909f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:compat5x-alpha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:compat5x-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:compat5x-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:compat5x-sparc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl-beta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl-beta-overwrite-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl-overwrite-base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"openssl<=0.9.7g")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openssl>=0.9.8<=0.9.8_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openssl>=0.9.*_20050325<=0.9.*_20051011")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openssl-overwrite-base<=0.9.7g")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openssl-overwrite-base>=0.9.8<=0.9.8_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openssl-overwrite-base>=0.9.*_20050325<=0.9.*_20051011")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openssl-beta<=0.9.8_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openssl-beta>=0.9.*_20050325<=0.9.*_20051011")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openssl-beta-overwrite-base<=0.9.8_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openssl-beta-overwrite-base>=0.9.*_20050325<=0.9.*_20051011")) flag++;
if (pkg_test(save_report:TRUE, pkg:"compat5x-alpha<5.4.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"compat5x-amd64<5.4.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"compat5x-i386<5.4.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"compat5x-sparc64<5.4.0.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
