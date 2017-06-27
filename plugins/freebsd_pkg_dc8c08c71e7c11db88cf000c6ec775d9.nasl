#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(22118);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/09/25 10:51:09 $");

  script_cve_id("CVE-2006-3747");
  script_xref(name:"CERT", value:"395412");

  script_name(english:"FreeBSD : apache -- mod_rewrite buffer overflow vulnerability (dc8c08c7-1e7c-11db-88cf-000c6ec775d9)");
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
"The Apache Software Foundation and The Apache HTTP Server Project
reports :

An off-by-one flaw exists in the Rewrite module, mod_rewrite, as
shipped with Apache 1.3 since 1.3.28, 2.0 since 2.0.46, and 2.2 since
2.2.0.

Depending on the manner in which Apache HTTP Server was compiled, this
software defect may result in a vulnerability which, in combination
with certain types of Rewrite rules in the web server configuration
files, could be triggered remotely. For vulnerable builds, the nature
of the vulnerability can be denial of service (crashing of web server
processes) or potentially allow arbitrary code execution. This issue
has been rated as having important security impact by the Apache HTTP
Server Security Team.

This flaw does not affect a default installation of Apache HTTP
Server. Users who do not use, or have not enabled, the Rewrite module
mod_rewrite are not affected by this issue. This issue only affects
installations using a Rewrite rule with the following characteristics
:

- The RewriteRule allows the attacker to control the initial part of
the rewritten URL (for example if the substitution URL starts with $1)

- The RewriteRule flags do NOT include any of the following flags:
Forbidden (F), Gone (G), or NoEscape (NE).

Please note that ability to exploit this issue is dependent on the
stack layout for a particular compiled version of mod_rewrite. If the
compiler used to compile Apache HTTP Server has added padding to the
stack immediately after the buffer being overwritten, it will not be
possible to exploit this issue, and Apache HTTP Server will continue
operating normally.

The Apache HTTP Server project thanks Mark Dowd of McAfee Avert Labs
for the responsible reporting of this vulnerability."
  );
  # http://marc.theaimsgroup.com/?l=apache-httpd-announce&m=115409818602955
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=apache-httpd-announce&m=115409818602955"
  );
  # http://www.freebsd.org/ports/portaudit/dc8c08c7-1e7c-11db-88cf-000c6ec775d9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e72d2d5e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Module mod_rewrite LDAP Protocol Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel+mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_accel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_accel+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache_fp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-apache+mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"apache>=1.3.28<1.3.36_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache>=2.0.46<2.0.58_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache>=2.2.0<2.2.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_perl>=1.3.28<1.3.36_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+ipv6>=1.3.28<1.3.37")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache_fp>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-apache>=1.3.28<1.3.37+30.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-apache+mod_ssl>=1.3.28<1.3.34.1.57_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+ssl>=1.3.28<1.3.34.1.57_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+ipv6>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel+ipv6>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel+mod_deflate>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel+mod_deflate+ipv6>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_deflate>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_deflate+ipv6>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_accel>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_accel+ipv6>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_deflate>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_deflate+ipv6>=1.3.28<1.3.36+2.8.27_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6>=1.3.28<1.3.36+2.8.27_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
