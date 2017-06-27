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
  script_id(81587);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/02 14:36:32 $");

  script_name(english:"FreeBSD : jenkins -- multiple vulnerabilities (7480b6ac-adf1-443e-a33c-3a3c0becba1e)");
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
"Kohsuke Kawaguchi from Jenkins team reports : DescriptionSECURITY-125
(Combination filter Groovy script unsecured) This vulnerability allows
users with the job configuration privilege to escalate his privileges,
resulting in arbitrary code execution to the master. SECURITY-162
(directory traversal from artifacts via symlink) This vulnerability
allows users with the job configuration privilege or users with commit
access to the build script to access arbitrary files/directories on
the master, resulting in the exposure of sensitive information, such
as encryption keys. SECURITY-163 (update center metadata retrieval DoS
attack) This vulnerability allows authenticated users to disrupt the
operation of Jenkins by feeding malicious update center data into
Jenkins, affecting plugin installation and tool installation.
SECURITY-165 (external entity injection via XPath) This vulnerability
allows users with the read access to Jenkins to retrieve arbitrary XML
document on the server, resulting in the exposure of sensitive
information inside/outside Jenkins. SECURITY-166
(HudsonPrivateSecurityRealm allows creation of reserved names) For
users using 'Jenkins' own user database' setting, Jenkins doesn't
refuse reserved names, thus allowing privilege escalation.
SECURITY-167 (External entity processing in XML can reveal sensitive
local files) This vulnerability allows attackers to create malicious
XML documents and feed that into Jenkins, which causes Jenkins to
retrieve arbitrary XML document on the server, resulting in the
exposure of sensitive information inside/outside Jenkins. Severity
SECURITY-125 is rated critical. This attack can be only mounted by
users with some trust, but it results in arbitrary code execution on
the master.

SECURITY-162 is rated critical. This attack can be only mounted by
users with some trust, but it results in the exposure of sensitive
information.

SECURITY-163 is rated medium, as it results in the loss of
functionality.

SECURITY-165 is rated critical. This attack is easy to mount, and it
results in the exposure of sensitive information.

SECURITY-166 is rated critical. For users who use the affected
feature, this attack results in arbitrary code execution on the
master.

SECURITY-167 is rated critical. This attack is easy to mount, and it
results in the exposure of sensitive information."
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2015-02-27
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a908b80"
  );
  # http://www.freebsd.org/ports/portaudit/7480b6ac-adf1-443e-a33c-3a3c0becba1e.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eefdfcad"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins-lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"jenkins<=1.600")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jenkins-lts<=1.580.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
