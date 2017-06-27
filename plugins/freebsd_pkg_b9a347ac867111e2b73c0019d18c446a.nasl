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
  script_id(65068);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/06/22 00:06:26 $");

  script_name(english:"FreeBSD : typo3 -- Multiple vulnerabilities in TYPO3 Core (b9a347ac-8671-11e2-b73c-0019d18c446a)");
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
"Typo Security Team reports :

Extbase Framework - Failing to sanitize user input, the Extbase
database abstraction layer is susceptible to SQL Injection. TYPO3
sites which have no Extbase extensions installed are not affected.
Extbase extensions are affected if they use the Query Object Model and
relation values are user generated input. Credits go to Helmut Hummel
and Markus Opahle who discovered and reported the issue.

Access tracking mechanism - Failing to validate user provided input,
the access tracking mechanism allows redirects to arbitrary URLs. To
fix this vulnerability, we had to break existing behaviour of TYPO3
sites that use the access tracking mechanism (jumpurl feature) to
transform links to external sites. The link generation has been
changed to include a hash that is checked before redirecting to an
external URL. This means that old links that have been distributed
(e.g. by a newsletter) will not work any more."
  );
  # http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2013-001/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6092781d"
  );
  # http://www.freebsd.org/ports/portaudit/b9a347ac-8671-11e2-b73c-0019d18c446a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?327e8692"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"typo3>=4.5.0<4.5.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"typo3>=4.6.0<4.6.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"typo3>=4.7.0<4.7.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"typo3>=6.0.0<6.0.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
