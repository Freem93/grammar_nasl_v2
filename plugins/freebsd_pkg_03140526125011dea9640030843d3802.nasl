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
  script_id(35998);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/21 23:43:34 $");

  script_xref(name:"Secunia", value:"34091");

  script_name(english:"FreeBSD : zabbix -- php frontend multiple vulnerabilities (03140526-1250-11de-a964-0030843d3802)");
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
"Secunia reports :

Some vulnerabilities have been reported in the ZABBIX PHP frontend,
which can be exploited by malicious people to conduct cross-site
request forgery attacks and malicious users to disclose sensitive
information and compromise a vulnerable system.

Input appended to and passed via the 'extlang' parameter to the
'calc_exp2()' function in include/validate.inc.php is not properly
sanitised before being used. This can be exploited to inject and
execute arbitrary PHP code.

The application allows users to perform certain actions via HTTP
requests without performing any validity checks to verify the
requests. This can be exploited to e.g. create users by enticing a
logged in administrator to visit a malicious web page.

Input passed to the 'srclang' parameter in locales.php (when 'next' is
set to a non-NULL value) is not properly verified before being used to
include files. This can be exploited to include arbitrary files from
local resources via directory traversal attacks and URL-encoded NULL
bytes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ush.it/team/ush/hack-zabbix_162/adv.txt"
  );
  # http://www.freebsd.org/ports/portaudit/03140526-1250-11de-a964-0030843d3802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed552317"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zabbix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"zabbix<1.6.2_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zabbix-agent<1.6.2_1,2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
