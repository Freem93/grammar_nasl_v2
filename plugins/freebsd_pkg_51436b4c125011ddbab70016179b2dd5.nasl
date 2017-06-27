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
  script_id(32063);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:31:55 $");

  script_cve_id("CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");
  script_bugtraq_id(27163);

  script_name(english:"FreeBSD : postgresql -- multiple vulnerabilities (51436b4c-1250-11dd-bab7-0016179b2dd5)");
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
"The PostgreSQL developers report :

PostgreSQL allows users to create indexes on the results of
user-defined functions, known as 'expression indexes'. This provided
two vulnerabilities to privilege escalation: (1) index functions were
executed as the superuser and not the table owner during VACUUM and
ANALYZE, and (2) that SET ROLE and SET SESSION AUTHORIZATION were
permitted within index functions. Both of these holes have now been
closed.

PostgreSQL allowed malicious users to initiate a denial-of-service by
passing certain regular expressions in SQL queries. First, users could
create infinite loops using some specific regular expressions. Second,
certain complex regular expressions could consume excessive amounts of
memory. Third, out-of-range backref numbers could be used to crash the
backend.

DBLink functions combined with local trust or ident authentication
could be used by a malicious user to gain superuser privileges. This
issue has been fixed, and does not affect users who have not installed
DBLink (an optional module), or who are using password authentication
for local access. This same problem was addressed in the previous
release cycle, but that patch failed to close all forms of the
loophole."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/about/news.905"
  );
  # http://www.freebsd.org/ports/portaudit/51436b4c-1250-11dd-bab7-0016179b2dd5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?962596d0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"postgresql>=7.3<7.3.21")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql>=7.4<7.4.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql>=8.0<8.0.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql>=8.1<8.1.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql>=8.2<8.2.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>=7.3<7.3.21")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>=7.4<7.4.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>=8.0<8.0.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>=8.1<8.1.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>=8.2<8.2.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
