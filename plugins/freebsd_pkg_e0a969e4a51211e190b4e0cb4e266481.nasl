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
  script_id(59283);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/22 00:10:44 $");

  script_cve_id("CVE-2011-0009", "CVE-2011-2082", "CVE-2011-2083", "CVE-2011-2084", "CVE-2011-2085", "CVE-2011-4458", "CVE-2011-4459", "CVE-2011-4460");

  script_name(english:"FreeBSD : RT -- Multiple Vulnerabilities (e0a969e4-a512-11e1-90b4-e0cb4e266481)");
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
"BestPractical report :

Internal audits of the RT codebase have uncovered a number of security
vulnerabilities in RT. We are releasing versions 3.8.12 and 4.0.6 to
resolve these vulnerabilities, as well as patches which apply atop all
released versions of 3.8 and 4.0.

The vulnerabilities addressed by 3.8.12, 4.0.6, and the below patches
include the following :

The previously released tool to upgrade weak password hashes as part
of CVE-2011-0009 was an incomplete fix and failed to upgrade passwords
of disabled users.

RT versions 3.0 and above contain a number of cross-site scripting
(XSS) vulnerabilities which allow an attacker to run JavaScript with
the user's credentials. CVE-2011-2083 is assigned to this
vulnerability.

RT versions 3.0 and above are vulnerable to multiple information
disclosure vulnerabilities. This includes the ability for privileged
users to expose users' previous password hashes -- this vulnerability
is particularly dangerous given RT's weak hashing previous to the fix
in CVE-2011-0009. A separate vulnerability allows privileged users to
obtain correspondence history for any ticket in RT. CVE-2011-2084 is
assigned to this vulnerability.

All publicly released versions of RT are vulnerable to cross-site
request forgery (CSRF). CVE-2011-2085 is assigned to this
vulnerability.

We have also added a separate configuration option
($RestrictLoginReferrer) to prevent login CSRF, a different class of
CSRF attack.

RT versions 3.6.1 and above are vulnerable to a remote execution of
code vulnerability if the optional VERP configuration options
($VERPPrefix and $VERPDomain) are enabled. RT 3.8.0 and higher are
vulnerable to a limited remote execution of code which can be
leveraged for privilege escalation. RT 4.0.0 and above contain a
vulnerability in the global $DisallowExecuteCode option, allowing
sufficiently privileged users to still execute code even if RT was
configured to not allow it. CVE-2011-4458 is assigned to this set of
vulnerabilities.

RT versions 3.0 and above may, under some circumstances, still respect
rights that a user only has by way of a currently-disabled group.
CVE-2011-4459 is assigned to this vulnerability.

RT versions 2.0 and above are vulnerable to a SQL injection attack,
which allow privileged users to obtain arbitrary information from the
database. CVE-2011-4460 is assigned to this vulnerability."
  );
  # http://blog.bestpractical.com/2012/05/security-vulnerabilities-in-rt.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ebd34bfd"
  );
  # http://www.freebsd.org/ports/portaudit/e0a969e4-a512-11e1-90b4-e0cb4e266481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9966cdaa"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rt38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rt40");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"rt40>=4.0<4.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rt38<3.8.12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
