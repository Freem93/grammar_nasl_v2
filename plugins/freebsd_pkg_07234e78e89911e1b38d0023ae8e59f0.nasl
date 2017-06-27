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
  script_id(61586);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/13 14:37:08 $");

  script_cve_id("CVE-2012-3488", "CVE-2012-3489");

  script_name(english:"FreeBSD : databases/postgresql*-server -- multiple vulnerabilities (07234e78-e899-11e1-b38d-0023ae8e59f0)");
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

The PostgreSQL Global Development Group today released security
updates for all active branches of the PostgreSQL database system,
including versions 9.1.5, 9.0.9, 8.4.13 and 8.3.20. This update
patches security holes associated with libxml2 and libxslt, similar to
those affecting other open source projects. All users are urged to
update their installations at the first available opportunity

Users who are relying on the built-in XML functionality to validate
external DTDs will need to implement a workaround, as this security
patch disables that functionality. Users who are using xslt_process()
to fetch documents or stylesheets from external URLs will no longer be
able to do so. The PostgreSQL project regrets the need to disable both
of these features in order to maintain our security standards. These
security issues with XML are substantially similar to issues patched
recently by the Webkit (CVE-2011-1774), XMLsec (CVE-2011-1425) and
PHP5 (CVE-2012-0057) projects."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/about/news/1407/"
  );
  # http://www.freebsd.org/ports/portaudit/07234e78-e899-11e1-b38d-0023ae8e59f0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3158a41e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/20");
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

if (pkg_test(save_report:TRUE, pkg:"postgresql-server>8.3.*<8.3.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>8.4.*<8.4.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>9.0.*<9.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql-server>9.1.*<9.1.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
