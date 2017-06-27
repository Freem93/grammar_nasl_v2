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
  script_id(59314);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/13 14:37:09 $");

  script_cve_id("CVE-2012-2143");

  script_name(english:"FreeBSD : databases/postgresql*-server -- crypt vulnerabilities (a8864f8f-aa9e-11e1-a284-0023ae8e59f0)");
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
"The PostgreSQL Global Development Group reports :

Today the PHP, OpenBSD and FreeBSD communities announced updates to
patch a security hole involving their crypt() hashing algorithms. This
issue is described in CVE-2012-2143. This vulnerability also affects a
minority of PostgreSQL users, and will be fixed in an update release
on June 4, 2012.

Affected users are those who use the crypt(text, text) function with
DES encryption in the optional pg_crypto module. Passwords affected
are those that contain characters that cannot be represented with
7-bit ASCII. If a password contains a character that has the most
significant bit set (0x80), and DES encryption is used, that character
and all characters after it will be ignored."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/about/news/1397/"
  );
  # http://git.postgresql.org/gitweb/?p=postgresql.git;a=patch;h=932ded2ed51e8333852e370c7a6dad75d9f236f9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51256ba9"
  );
  # http://www.freebsd.org/ports/portaudit/a8864f8f-aa9e-11e1-a284-0023ae8e59f0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aaa75e0f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"postgresql-server>8.3.*<8.3.18_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>8.4.*<8.4.11_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>9.0.*<9.0.7_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>9.1.*<9.1.3_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>9.2.*<9.2.b1_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
