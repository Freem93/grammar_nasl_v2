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
  script_id(22208);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/09 15:44:46 $");

  script_cve_id("CVE-2006-2313", "CVE-2006-2314");
  script_bugtraq_id(18092);

  script_name(english:"FreeBSD : postgresql -- encoding based SQL injection (17f53c1d-2ae9-11db-a6e2-000e0c2e438a)");
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
"The PostgreSQL development team reports :

An attacker able to submit crafted strings to an application that will
embed those strings in SQL commands can use invalidly-encoded
multibyte characters to bypass standard string-escaping methods,
resulting in possible injection of hostile SQL commands into the
database. The attacks covered here work in any multibyte encoding.

The widely-used practice of escaping ASCII single quote ''' by turning
it into '\'' is unsafe when operating in multibyte encodings that
allow 0x5c (ASCII code for backslash) as the trailing byte of a
multibyte character; this includes at least SJIS, BIG5, GBK, GB18030,
and UHC. An application that uses this conversion while embedding
untrusted strings in SQL commands is vulnerable to SQL-injection
attacks if it communicates with the server in one of these encodings.
While the standard client libraries used with PostgreSQL have escaped
''' in the safe, SQL-standard way of '''' for some time, the older
practice remains common."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/techdocs.50"
  );
  # http://www.freebsd.org/ports/portaudit/17f53c1d-2ae9-11db-a6e2-000e0c2e438a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a6adc31"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"postgresql>=7.3<7.3.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql>=7.4<7.4.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql>=8.0.0<8.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql>=8.1.0<8.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>=7.3<7.3.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>=7.4<7.4.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>=8.0.0<8.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>=8.1.0<8.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-postgresql>=7.3<7.3.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-postgresql>=7.4<7.4.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-postgresql>=8.0.0<8.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-postgresql>=8.1.0<8.1.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
