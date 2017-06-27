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
  script_id(88945);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/02/25 16:05:29 $");

  script_name(english:"FreeBSD : jenkins -- multiple vulnerabilities (7e01df39-db7e-11e5-b937-00e0814cab4e)");
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
"Jenkins Security Advisory : DescriptionSECURITY-232 /
CVE-2016-0788(Remote code execution vulnerability in remoting module)
A vulnerability in the Jenkins remoting module allowed unauthenticated
remote attackers to open a JRMP listener on the server hosting the
Jenkins master process, which allowed arbitrary code execution.
SECURITY-238 / CVE-2016-0789(HTTP response splitting vulnerability) An
HTTP response splitting vulnerability in the CLI command documentation
allowed attackers to craft Jenkins URLs that serve malicious content.
SECURITY-241 / CVE-2016-0790(Non-constant time comparison of API
token) The verification of user-provided API tokens with the expected
value did not use a constant-time comparison algorithm, potentially
allowing attackers to use statistical methods to determine valid API
tokens using brute-force methods. SECURITY-245 /
CVE-2016-0791(Non-constant time comparison of CSRF crumbs) The
verification of user-provided CSRF crumbs with the expected value did
not use a constant-time comparison algorithm, potentially allowing
attackers to use statistical methods to determine valid CSRF crumbs
using brute-force methods. SECURITY-247 / CVE-2016-0792(Remote code
execution through remote API) Jenkins has several API endpoints that
allow low-privilege users to POST XML files that then get deserialized
by Jenkins. Maliciously crafted XML files sent to these API endpoints
could result in arbitrary code execution."
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Security+Advisory+2016-02-24
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c87d9d2e"
  );
  # http://www.freebsd.org/ports/portaudit/7e01df39-db7e-11e5-b937-00e0814cab4e.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?367b1645"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins-lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"jenkins<=1.650")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jenkins-lts<=1.642.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
