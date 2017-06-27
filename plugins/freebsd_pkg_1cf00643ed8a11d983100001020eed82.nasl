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
  script_id(18859);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/21 23:43:36 $");

  script_name(english:"FreeBSD : cacti -- multiple vulnerabilities (1cf00643-ed8a-11d9-8310-0001020eed82)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stefan Esser reports :

Wrongly implemented user input filters lead to multiple SQL Injection
vulnerabilities which can lead f.e. to disclosure of the admin
password hash.

Wrongly implemented user input filters allows injection of user input
into executed commandline.

Alberto Trivero posted his Remote Command Execution Exploit for Cacti
<= 0.8.6d to Bugtraq on the 22th June. Having analysed his bug we come
to the conclusion, that the malfunctioning input filters, which were
already mentioned in the previous advisory are also responsible for
this bug still being exploitable.

A HTTP headers bypass switch can also be used to completely bypass the
authentification system of Cacti. As admin it is possible to execute
shell commands with the permission of the webserver.

While looking at the source of Cacti a HTTP headers bypass switch was
discovered, that also switches off a call to session_start() and the
manual application of addslashes() in case of magic_quotes_gpc=Off.

When register_globals is turned on* an attacker can use this switch to
disables Cacti's use of PHP's session support and therefore supply the
session variables on his own through f.e. the URL. Additionally using
the switch renders several SQL statements vulnerable to SQL Injections
attacks, when magic_quotes_gpc is turned off, which is the recommended
setting.

Logged in as an admin it is possible to issue shell commands.

(*) register_globals is turned off by default since PHP 4.2 but is
activated on most servers because of older scripts requiring it."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=111954136315248
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=111954136315248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory-032005.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory-042005.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory-052005.php"
  );
  # http://www.freebsd.org/ports/portaudit/1cf00643-ed8a-11d9-8310-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a13d95de"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"cacti<0.8.6f")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
