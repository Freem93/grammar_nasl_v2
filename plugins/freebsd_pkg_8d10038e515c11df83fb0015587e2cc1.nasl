#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(46005);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/12 14:36:12 $");

  script_name(english:"FreeBSD : joomla -- multiple vulnerabilities (8d10038e-515c-11df-83fb-0015587e2cc1)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joomla! reported the following vulnerabilities :

If a user entered a URL with a negative query limit or offset, a PHP
notice would display revealing information about the system..

The migration script in the Joomla! installer does not check the file
type being uploaded. If the installation application is present, an
attacker could use it to upload malicious files to a server.

Session id doesn't get modified when user logs in. A remote site may
be able to forward a visitor to the Joomla! site and set a specific
cookie. If the user then logs in, the remote site can use that cookie
to authenticate as that user.

When a user requests a password reset, the reset tokens were stored in
plain text in the database. While this is not a vulnerability in
itself, it allows user accounts to be compromised if there is an
extension on the site with a SQL injection vulnerability."
  );
  # http://developer.joomla.org/security/news/308-20100423-core-password-reset-tokens.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4210cdd8"
  );
  # http://developer.joomla.org/security/news/309-20100423-core-sessation-fixation.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4553eaf3"
  );
  # http://developer.joomla.org/security/news/310-20100423-core-installer-migration-script.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e31c4775"
  );
  # http://developer.joomla.org/security/news/311-20100423-core-negative-values-for-limit-and-offset.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85d5e95a"
  );
  # http://www.freebsd.org/ports/portaudit/8d10038e-515c-11df-83fb-0015587e2cc1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5912550"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:joomla15");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"joomla15>=1.5.1<=1.5.15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
